import sys
import signal
import datetime
import logging
import traceback
import yaml
import requests

def kill_signal_handler(signal, frame):
    print("\nExecution interrupted.")
    sys.exit(0)

signal.signal(signal.SIGINT, kill_signal_handler)

class Breach:
    def __init__(self, args):
        self.args = args
        self.setup_logger()
        self.logger = logging.getLogger('debug_logger')

    def setup_logger(self):
        level = logging.DEBUG if self.args.get('verbose', 0) > 1 else logging.INFO
        logging.basicConfig(filename=self.args.get('log_file', 'debug.log'),
                            level=level,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def send_request(self, payload):
        url = self.args['url']
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(url, headers=headers, data=payload)
            return response
        except Exception as e:
            self.logger.error(f"Error sending request: {e}")
            return None

    def execute_attack(self):
        self.logger.info("Starting BREACH attack simulation.")
        payloads = ["A" * i for i in range(10, 50)]  # Example payloads
        for payload in payloads:
            response = self.send_request(payload)
            if response and response.ok:
                self.logger.debug(f"Payload: {payload} | Response Length: {len(response.content)}")
        self.logger.info("Attack simulation complete.")

if __name__ == '__main__':
    try:
        with open('config.yml', 'r') as ymlconf:
            cfg = yaml.safe_load(ymlconf)

        args = cfg['execution']
        args.update(cfg['endpoint'])
        args.update(cfg['local'])
        args.update(cfg['logging'])
        args['start_time'] = datetime.datetime.now()

        breach = Breach(args)
        breach.execute_attack()

    except Exception as e:
        print("An error occurred:", e)
        traceback.print_exc()
