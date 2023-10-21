import asyncio
import serial
import threading

CMD = 0
VOLT = 0

###################################### SERVER ZONE ###################################### 
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/BASE",)

server = SimpleXMLRPCServer(("192.168.0.201", 8001), requestHandler=RequestHandler, logRequests=False)

def check():
    return "ok"

def ReadVOLT():
    global VOLT
    #print("Прочитано значение ", VOLT)
    return VOLT

def WritePWM(pwm_):
    global CMD
    if(pwm_ == 0):
        CMD = 0
    elif(pwm_ == 100):
        CMD = 2
    else:
        CMD = 1
    print("Записана команда ", CMD)
    return 0

server.register_function(ReadVOLT, "ReadVOLT")
server.register_function(WritePWM, "WritePWM")
server.register_function(check, "check")

def server_run():
    print("Запуск сервера XML-RPC...")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

###################################### SERIAL ZONE ###################################### 
async def read_serial_data(ser):
    buffer = b"" 
    while True:
        data = await loop.run_in_executor(None, ser.read, 1)  # Асинхронное чтение одного байта
        buffer += data
        if b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            process_data(line.decode())

def process_data(data):
    if data.startswith("data:"):
        global VOLT
        _, value, _ = data.split(":")
        #print(f"Received value: {value}")
        VOLT = int(value)

async def send_serial_command(ser):
    global CMD
    while True:
        cmd = f"cmd{CMD}end\n"
        ser.write(cmd.encode())
        await asyncio.sleep(0.1)

async def main():	#'COM9',
    ser = serial.Serial("COM9", 115200)
    server_run()
    await asyncio.gather(
        read_serial_data(ser),
        send_serial_command(ser),
    )

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
