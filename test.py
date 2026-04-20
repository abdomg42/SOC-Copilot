from os import path

from neo4j import GraphDatabase
import json, os 
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()


# _driver = None
# def get_driver():
#     global _driver
#     if _driver is None:
#         _driver = GraphDatabase.driver(
#             os.getenv('NEO4J_URI'),
#             auth=(os.getenv('NEO4J_USER'), os.getenv('NEO4J_PASSWORD'))
#         )
#     print(_driver)
#     return _driver

# print(get_driver().verify_connectivity())

# def return_all():
#     with get_driver().session() as s :
#         res = s.run("MATCH (n) RETURN n").data()
#     print(res)

# if __name__ == "__main__":
    # return_all()
path = "C:\\Users\\PC\\projects\\soc-copilot\\data\\d3fend\\d3fend.csv"
with open(path ,encoding='utf-8') as f:
            lines = f.readlines()
            print(lines[5])
