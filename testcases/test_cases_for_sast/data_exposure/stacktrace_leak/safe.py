import logging
try:
    1/0
except Exception as e:
    logging.error("An error occurred", exc_info=False)
