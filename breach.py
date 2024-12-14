import requests
import logging
import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class BreachDetector:
    def __init__(self, target_url, payloads):
        self.target_url = target_url
        self.payloads = payloads

    def test_breach_vulnerability(self):
        """
        Test if the server uses vulnerable compression methods.
        """
        try:
            response = requests.get(self.target_url)
            encoding = response.headers.get('Content-Encoding', '')
            if encoding in ['gzip', 'deflate']:
                logger.warning(f"[VULNERABLE] The server uses {encoding} compression. This may indicate BREACH vulnerability.")
            else:
                logger.info(f"[SAFE] The server does not use compression methods vulnerable to BREACH.")
        except Exception as e:
            logger.error(f"Error during request: {e}")

    def analyze_payloads(self):
        """
        Analyze response sizes based on different payloads to detect potential vulnerability.
        """
        previous_response_size = None
        try:
            for payload in self.payloads:
                response = requests.post(self.target_url, data={"input": payload})
                current_response_size = len(response.content)
                logger.info(f"Payload: {payload} | Response Size: {current_response_size} bytes")
                if previous_response_size and current_response_size != previous_response_size:
                    logger.warning(f"Response size changed for payload {payload}. This may indicate vulnerability to BREACH.")
                
                previous_response_size = current_response_size
        except Exception as e:
            logger.error(f"Error during payload analysis: {e}")

    def save_results_to_file(self, results, filename="results.log"):
        """
        Save test results to a log file.
        """
        try:
            with open(filename, "w") as file:
                file.write(results)
            logger.info(f"Results saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving results to file: {e}")

def load_config(config_file="config.yml"):
    """
    Load configuration from a YAML file.
    """
    try:
        with open(config_file, "r") as file:
            config = yaml.safe_load(file)
        return config
    except Exception as e:
        logger.error(f"Error loading configuration file: {e}")
        return None

if __name__ == "__main__":
    config = load_config("config.yml")
    if config is None:
        logger.error("Failed to load configuration.")
        exit(1)

    target_url = config.get('target_url', '')
    payloads = config.get('payloads', [])

    if not target_url or not payloads:
        logger.error("Target URL or payloads are missing in the configuration.")
        exit(1)

    logger.info("Starting BREACH vulnerability detection...")
    breach_detector = BreachDetector(target_url, payloads)
    breach_detector.test_breach_vulnerability()
    breach_detector.analyze_payloads()

    logger.info("BREACH vulnerability detection completed.")
