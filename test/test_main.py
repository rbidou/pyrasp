# test_flaskrap.py
import requests

BASE_URL = "http://localhost:8080"


def test_normal_request():
    r = requests.get(f"{BASE_URL}", params={"msg": "hello"})

    assert r.status_code == 200
    assert r.json()["received"] == "hello"


def test_sql_injection_attempt():
    payload = "' OR '1'='1"

    r = requests.get(f"{BASE_URL}/hello", params={"msg": payload})

    # Adjust according to FlaskRAP expected behavior
    assert r.status_code in [403, 406, 400]
