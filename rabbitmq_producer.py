import pika
import json
from decimal import Decimal

rabbitmq_host = 'rabbitmq.rabbitmq.svc.cluster.local' 
rabbitmq_port = 5672
rabbitmq_user = 'guest'  
rabbitmq_password = 'guest'
 
def get_rabbitmq_connection():
    credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_password)
    parameters = pika.ConnectionParameters(rabbitmq_host,
                                           rabbitmq_port,
                                           '/',
                                           credentials)
    return pika.BlockingConnection(parameters)

def convert_decimal(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimal(i) for i in obj]
    return obj

def publish_message(queue, message):
    connection = get_rabbitmq_connection()
    channel = connection.channel()
    print('publishing')
    message = convert_decimal(message)
    channel.basic_publish(exchange='', routing_key=queue, body=json.dumps(message))
    connection.close()
