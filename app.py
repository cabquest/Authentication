from flask import Flask, json, request, jsonify, url_for,abort, render_template, flash, redirect,current_app, send_from_directory
from flask_bcrypt import Bcrypt, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from flask_migrate import Migrate
from models import db,Admin, User, Profile, Temp_user, Driver, Driver_verification, Vehicle_details, Vehicle_type
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_session import Session
import random, os
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf, CSRFError
from wtforms.validators import ValidationError
from itsdangerous import URLSafeTimedSerializer
from datetime import timedelta
from werkzeug.utils import secure_filename
from rabbitmq_producer import publish_message
from decimal import Decimal

load_dotenv()

app = Flask(__name__)

app.config['MAIL_PASSWORD'] = os.environ["GOOGLE_APP_PASSWORD"]
app.config['SECRET_KEY'] = os.environ["SECRET_KEY"]
app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['SECURITY_PASSWORD_SALT'] = os.environ['SECURITY_PASSWORD_SALT']
# SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://authentication:authentication@localhost:33067/authentication'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://authentication:authentication@host.docker.internal:33067/authentication'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SESSION_TYPE'] = 'filesystem' 
# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'cabquest.buisness@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ["GOOGLE_APP_PASSWORD"]

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
db.init_app(app)
jwt.init_app(app)
CORS(app, supports_credentials=True)
mail = Mail(app)
Session(app)


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

def send_mail(email,fullname,otp):
    msg = Message('Your OTP Code', sender='cabquest.buisness@gmail.com', recipients=[email])
    msg.body = f"""
        Dear {fullname},

        Thank you for choosing our taxi service!

        To complete your registration/sign-in, please use the following One-Time Password (OTP):

        {otp}

        This code is valid for the next 10 minutes. Please do not share this code with anyone.

        If you did not request this OTP, please ignore this message.

        Thank you,
        cabQuest Team
        """
    try:
        mail.send(msg)
        return 'Email sent successfully!'
    except Exception as e:
        return str(e)
    
def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_USERNAME']
    )
    mail.send(msg)
    
def generate_otp():
    otp = random.randint(11111,99999)
    return otp

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({
        'accessToken': new_access_token
    }), 200

@app.route('/',methods=["GET"])
def hello():
    users = User.query.all()
    # user_list = [{'id': user.id, 'fullname': user.fullname, 'email': user.email, 'phone': user.phone,  'password':user.password, 'verified':user.KYC_verified } for user in users]
    # users = Driver.query.filter_by(KYC_verified = False)
    # users = Driver_verification.query.all()
    # user_list = [{'id':user.id, 'license':user.license,'aadhar':user.aadhar,'pan_card':user.pan_card,'profile_pic':user.profile_pic,'driver_id':user.driver_id} for user in users]
    # users = Vehicle_details.query.all()
    for i in users:
        db.session.delete(i)
        db.session.commit()
    # user_list = [{'make': user.make, 'model': user.model, 'RC': user.RC, 'license_plate': user.license_plate,  'insurance':user.insurance,'vehicle_type_id':user.vehicle_type_id } for user in users]
    user_list = [{'id': user.id, 'fullname': user.fullname, 'email': user.email, 'phone': user.phone,  'password':user.password } for user in users]
    return jsonify(user_list)

@app.route('/register',methods=['POST','GET'])
def user_register():
    if 'fullname' not in request.json or 'email' not in request.json or 'phone' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Missing required fields'}), 400
    
    fullname = str(request.json.get('fullname'))
    email = str(request.json.get('email'))
    phone = str(request.json.get('phone'))
    password = str(request.json.get('password'))

    if User.query.filter_by(email=email).first():
        return jsonify({'message':'email is already used'})

    if Temp_user.query.filter_by(email = email).first():
        user = Temp_user.query.filter_by(email = email).first()
        db.session.delete(user)
        db.session.commit()

    otp = generate_otp()
    print(otp)

    send_mail(email,fullname,otp)

    temp_user = Temp_user(fullname = fullname, email = email, phone = phone, password = password, otp = otp)
    db.session.add(temp_user)
    db.session.commit()
    
    return jsonify({'message': 'User recorded'}), 200

@app.route('/verify',methods=['POST','GET'])
def creating_user():
    
    otp = request.json.get('otp')
    email = request.json.get('email')

    try:
        user = Temp_user.query.filter_by(email = email).first()
    except:
        return jsonify({'message':'user is not found'})

    fullname = user.fullname
    email = user.email
    phone = user.phone
    password = user.password
    otp2 = user.otp
    db.session.delete(user)
    db.session.commit()

    if str(otp) == str(otp2):
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
        new_user = User(fullname=fullname, email=email, phone=phone, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        user_for_booking = {'id':new_user.id,'fullname':new_user.fullname, 'email':new_user.email, 'phone':new_user.phone,'role':'user'}
        publish_message('Booking',user_for_booking)
        publish_message('ride',user_for_booking)
        publish_message('communication',user_for_booking)
        return jsonify({'message':"Account Created"}),200
    return jsonify({'message': 'Invalid OTP'}), 400

@app.route('/signin',methods=['POST'])
def user_login():
    print('entered')
    data = request.get_json()
    print(f"Received data: {data}")

    email = request.json.get('email')
    password = request.json.get('password')
    
    print(email, password)
    try:
        user = User.query.filter_by(email=email).first()
    except:
        return jsonify({'message': 'Invalid email or password'})
    
    if user and check_password_hash(user.password, password):

        access_token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)

        return jsonify({'message': 'Login successful','tokens':{
        "accessToken":access_token,
        "refreshToken":refresh_token,
        "fullname":user.fullname
        }}), 200

    return jsonify({'message':'Invalid Credentials'})

@app.route('/driver_register', methods=['POST'])
def driver_register():
    data = request.get_json()
    fullname = data['fullname']
    email = data['email']
    password = data['password']
    phone = data['phone']
    print(fullname,email,password,phone)

    try:
        user = Driver.query.filter_by(email=email).first()
        if user:
            print('user')
            return jsonify({"message": "Email address already exists"})
    except:
        pass
    
    try:
        user = Driver.query.filter_by(phone=phone).first()
        if user:
            print('user')
            return jsonify({"message": "Phone number already exists"})
    except:
        pass
    
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Driver(fullname = fullname, email=email, password = hashed_password, phone = phone)
    db.session.add(new_user)
    db.session.commit()

    token = generate_confirmation_token(email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('verify_email.html', confirm_url=confirm_url)
    send_email(email, 'Please confirm your email', html)

    return jsonify({"message": "A confirmation email has been sent."}),200

@app.route('/api/confirm/<token>',methods=['GET'])
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        return jsonify({"message": "The confirmation link is invalid or has expired."}), 400
    user = Driver.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        return redirect('http://localhost:3000/login_driver')
    else:
        user.is_verified = True
        db.session.add(user)
        db.session.commit()
        
        return redirect('http://localhost:3000/email_verified')

@app.route('/driver_auth',methods=["POST"])
def driver_login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    try:
        user = Driver.query.filter_by(email=email).first()
    except:
        return jsonify({'message': 'Invalid email or password'})
    
    if user and check_password_hash(user.password, password):

        access_token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)
        verified = False
        if user.is_verified == True:
            verfied = True

        return jsonify({'message': 'Login successful','d_tokens':{
        "accessToken":access_token,
        "refreshToken":refresh_token,
        "fullname":user.fullname,
        "verified":verified,
        "kyc":user.KYC_verified
        }}), 200
    return jsonify({'message':'Invalid Credentials'})   

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/driver_kyc',methods=["POST"])
def driver_kyc():
    form_data = request.form.to_dict()
    email = form_data.get('email')
    print(form_data)
    print(email)

    try:
        user = Driver.query.filter_by(email = email).first()
    except:
        return jsonify({'message':'user not available try login once again'})
    
    try:
        driver = Driver_verification.query.filter_by(driver_id = user.id).first()
        if driver:
            return jsonify({'message':'details already recorded'})
    except:
        pass

    try:
        files = request.files.to_dict()
        saved_files = {}
        for key, file in files.items():
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                saved_files[key] = file_path
            else:
                return jsonify({'message':f'{filename} not allowed'})
        
        verification_data = Driver_verification(
            license=saved_files.get('Driving License', ''),
            aadhar=saved_files.get('Aadhar Card', ''),
            pan_card=saved_files.get('PAN Card', ''),
            profile_pic=saved_files.get('Profile Photo', ''),
            driver_id=user.id
        )

        vehicle_data = Vehicle_details(
            RC = saved_files.get("Registration Certificate (RC)", ''),
            insurance = saved_files.get('Insurance', ''),
            driver_id = user.id
        )

        db.session.add(verification_data)
        db.session.add(vehicle_data)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Server error, try again later', 'error': str(e)})

    return jsonify({'message':'files successfully uploaded'})

@app.route('/vehicle',methods=['POST','GET'])
def vehicle():
    if request.method == 'GET':
        vehicles = Vehicle_type.query.all()
        vehicle_list = [{'id': vehicle.id, 'type': vehicle.type, 'base_price': vehicle.base_price, 'base_distance_KM': vehicle.base_distance_KM,  'price_per_KM':vehicle.price_per_km} for vehicle in vehicles]
        return jsonify(vehicle_list)
    else:
        data = request.get_json()
        type = data['type']
        model = data['model']
        year = data['year']
        plate = data['plate']
        email = data['email']
        try:
            user = Driver.query.filter_by(email = email).first()
        except:
            return jsonify({'message':"Driver not available try again login"})
        try:
            vehicle_detail = Vehicle_details.query.filter_by(driver_id = user.id).first()
            if vehicle_detail:
                Type = Vehicle_type.query.filter_by(type = type).first()
                vehicle_detail.vehicle_type_id = Type.id
                vehicle_detail.model = model
                vehicle_detail.make = year
                vehicle_detail.license_plate = plate

                db.session.commit()
                return jsonify({'message':'Successfully added'})
            else:
                return jsonify({'message':'No vehicle details found for the specified driver'})

        except:
            return jsonify({'message':"first step seems not completed try again"})

@app.route('/addvehicle',methods = ['POST'])
def add_vehicle():
    try:
        json_data = request.get_json()
        print(json_data)
        data = json.loads(json_data['jsonFormData'])
        print(data['type'])
        vehicles = Vehicle_type(type = data['type'], base_price = data['base_price'], base_distance_KM = data['base_distance_KM'], price_per_km = data['price_per_km'])
        db.session.add(vehicles)
        db.session.commit()
        print(vehicles)
        return jsonify({'message':'vehicle successfully added'})
    except Exception as e:
        print(e)
        db.session.rollback()
        return jsonify({'message':'something not found'})


@app.route('/driver_verification',methods = ["GET"])
def driver_verification():
    drivers = Driver.query.filter_by(KYC_verified = False)
    identities = []
    for i in drivers:
        verification = Driver_verification.query.filter_by(driver_id = i.id).first()
        vehicle = Vehicle_details.query.filter_by(driver_id = i.id).first()
        if vehicle:
            Type = Vehicle_type.query.filter_by(id = vehicle.vehicle_type_id).first()
            my_dict = {
                'id':i.id,
                'providerName':i.fullname,
                'vehicle':Type.type,
                'dl':verification.license,
                'pan':verification.pan_card,
                'insurance':vehicle.insurance,
                'rc':vehicle.RC
            }
            identities.append(my_dict)
    return jsonify(identities)

@app.route('/verify_register',methods = ["POST"])
def verify_register():
    data = request.get_json()
    email = data['email']
    user = Driver.query.filter_by(email = email).first()
    try:
        verification = Driver_verification.query.filter_by(driver_id = user.id).first()
        if verification:
            return jsonify({'message':'registration already recorded'})
        else:
            return jsonify({'message':'okk'})
    except:
        return jsonify({'message':'ok'})
    

@app.route('/uploads/<fileName>', methods=['GET'])
def download_file(fileName):
    print('yhello')
    print(fileName)
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], fileName, as_attachment=True)
    except FileNotFoundError:
        print('not')

@app.route('/accept',methods = ["POST"])
def accept():
    driver = Driver.query.filter_by(id = request.get_json()['id']).first()
    driver.KYC_verified = True
    db.session.commit()
    vehicle = Vehicle_details.query.filter_by(driver_id = driver.id).first()
    vehicle_type = Vehicle_type.query.filter_by(id = vehicle.vehicle_type_id).first()
    user = {
        'id':driver.id,
        'fullname':driver.fullname, 
        'email':driver.email, 
        'phone':driver.phone, 
        'role':'driver', 
        'vehicle_type':vehicle_type.type,
        'base_price':Decimal(vehicle_type.base_price), 
        'base_distance_KM':vehicle_type.base_distance_KM, 
        'price_per_km':Decimal(vehicle_type.price_per_km),
        'make':vehicle.make,
        'model':vehicle.model,
        'license_plate':vehicle.license_plate,
        }
    publish_message('Booking',user)
    user2 = {
        'id':driver.id,
        'fullname':driver.fullname, 
        'email':driver.email, 
        'phone':driver.phone, 
        'role':'driver', 
    }
    publish_message('ride',user2)
    publish_message('communication',user2)
    return jsonify({'message':'ok'})

@app.route('/drivers',methods = ["GET"])
def drivers():
    driver = Driver.query.filter_by(KYC_verified = True)
    user_list = [{'id': user.id, 'fullname': user.fullname, 'email': user.email, 'phone': user.phone,  'status':user.status,} for user in driver]
    return jsonify(user_list)

@app.route('/searchdriver', methods = ["POST"])
def searchdriver():
    data = request.get_json()
    val = data['val']
    drivers = Driver.query.filter(
        Driver.KYC_verified == True,
        Driver.fullname.startswith(f'{val}')
    ).all()
    user_list = [{'id': user.id, 'fullname': user.fullname, 'email': user.email, 'phone': user.phone,  'status':user.status,} for user in drivers]
    return jsonify(user_list)


@app.route('/admin',methods=["POST"])
def admin():
    data = request.get_json()
    fullname = data['fullname']
    email = data['email']
    phone = data['phone']
    password = data['password']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    admin = Admin(fullname = fullname, email = email, phone = phone, password = hashed_password)
    db.session.add(admin)
    db.session.commit()
    return jsonify({'message':'added successfully'})

@app.route('/admin_login',methods = ["POST"])
def admin_login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    try:
        admin = Admin.query.filter_by(email = email).first()
        if admin and check_password_hash(admin.password, password):
            access_token = create_access_token(identity=admin.email)
            refresh_token = create_refresh_token(identity=admin.email)

            return jsonify({'message': 'Login successful','a_tokens':{
            "accessToken":access_token,
            "refreshToken":refresh_token,
            "fullname":admin.fullname
            }}), 200
    except:
        return jsonify({'message':'admin not found'})

@app.route('/isdriververified',methods = ["POST"])
def isdriververified():
    data = request.get_json()
    email = data['email']
    try:
        driver = Driver.query.filter_by(email = email).first()
        if driver.KYC_verified:
            return jsonify({'message':'true'})
        else:
            return jsonify({'message':'false'})
    except:
        return jsonify({'message':'driver not found'})

@app.route('/isvehicleadded',methods = ['POST'])
def isvehicleadded():
    data = request.get_json()
    email = data['email']
    try:
        driver = Driver.query.filter_by(email = email).first()
        vehicle = Vehicle_details.query.filter_by(driver_id = driver.id).first()
        if vehicle.license_plate:
            return jsonify({'message':'vehicle already added'})
        else:
            return json({'message':'vehicle not added'})
    except:
        return jsonify({'message':'error'})

@app.route('/makeactive',methods = ["POST"])
def makeactive():
    data = request.get_json()
    print(data)
    try:
        user = Driver.query.filter_by(email = data['email']).first()
        user.status = 'active'
        user.latitude = data['location']['latitude']
        user.longitude = data['location']['longitude']
        db.session.commit()
        message = {'email':data['email'], 'latitude':data['location']['latitude'], 'longitude':data['location']['longitude'], 'role':'makeactive','status':'active'}
        publish_message('Booking',message)
        return jsonify({'message':'ok'})
    except:
        return jsonify({'message':'error'})

@app.route('/makeinactive',methods = ["POST"])
def makeinactive():
    data = request.get_json()
    print(data)
    try:
        user = Driver.query.filter_by(email = data['email']).first()
        user.status = 'inactive'
        user.latitude = data['loc']['latitude']
        user.longitude = data['loc']['longitude']
        db.session.commit()
        message = {'email':data['email'], 'latitude':data['loc']['latitude'], 'longitude':data['loc']['longitude'], 'role':'makeactive', 'status':'inactive'}
        publish_message('Booking',message)
        return jsonify({'message':'ok'})
    except:
        return jsonify({'message':'error'})

@app.route('/driveaccept',methods = ["POST"])
def driveaccept():
    data = request.get_json()
    email = data['email']
    driver = Driver.query.filter_by(email = email).first()
    driver.status = 'onwork'
    db.session.commit()
    message = {'email':email,'role':'onwork'}
    publish_message('Booking',message)

    return jsonify({'message':'ok'})

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=9639)
