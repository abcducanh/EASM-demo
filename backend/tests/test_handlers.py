from fastapi.testclient import TestClient

from app.main import app
from app.storage.memory import store

client = TestClient(app)


def setup_function():
    store.reset()


def test_create_asset_handler():
    response = client.post('/assets', json={'name': 'test.com', 'type': 'domain'})

    assert response.status_code == 201
    payload = response.json()
    assert payload['name'] == 'test.com'
    assert payload['type'] == 'domain'


def test_create_asset_handler_rejects_invalid_payload():
    response = client.post('/assets', json={'name': 'bad value', 'type': 'domain'})

    assert response.status_code == 422


def test_list_and_delete_asset_handlers():
    created = client.post('/assets', json={'name': '127.0.0.1', 'type': 'ip'}).json()
    listing = client.get('/assets')
    deleted = client.delete(f"/assets/{created['id']}")
    empty = client.get('/assets')

    assert listing.status_code == 200
    assert len(listing.json()) == 1
    assert deleted.status_code == 200
    assert deleted.json()['deleted'] is True
    assert empty.json() == []


def test_health_handler():
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {'status': 'ok'}
