import os 
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = "mysql+pymysql://{}:{}@127.0.0.1:3306/network_analyzer".format(
    os.getenv("DB_USER"),
    os.getenv("DB_PASSWORD")
)



