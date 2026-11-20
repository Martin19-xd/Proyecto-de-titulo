import pytest
from fastapi.testclient import TestClient
from url_guard.core import AnalizadorURL, CATALOG
from url_guard.presentation import band_for, format_percent, public_result


@pytest.mark.parametrize('p,expected', [(0,0),(.009999,0),(.01,1),(.05,1),(.05001,2),(.2,2),(.20001,3),(.5,3),(.50001,4),(1,4)])
def test_display_boundaries(p, expected):
    assert band_for(p) == expected


def test_percent_does_not_round_across_boundary():
    assert format_percent(.009999) == '0,99 %'
    assert format_percent(0) == 'Menos de 0,01 %'
    assert format_percent(1) == 'Más de 99,99 %'
    assert format_percent(.05001) == 'Más de 5 %'


@pytest.fixture(scope='module')
def analyzer():
    return AnalizadorURL('artifacts/selected.joblib')


def test_bank_route_abstains_without_discarding_path_or_model_score(analyzer):
    url = 'https://www.bancoestado.cl/content/bancoestado-public/cl/es/home/home.html#/'
    r = analyzer.analizar(url)
    assert r['observed_features']['path_length'] > 0
    assert r['p_phishing'] > .5
    assert r['model_classification'] == 'likely_suspicious'
    assert r['classification'] == 'caution'
    assert r['reference_conflict']
    public = public_result(r)
    assert public['status'] == 'uncertain'
    assert public['percent'] is None


@pytest.mark.parametrize('url', ['https://bancoestado.cl.ejemplo.test/content/home', 'https://bancoestado.cl@ejemplo.com/home', 'https://ejemplo.com/bancoestado.cl', 'https://bancoestadofalso.com'])
def test_brand_text_does_not_recognize_destination(analyzer, url):
    r = analyzer.analizar(url)
    assert not r['reference']['hostname_matches']
    assert r['reference']['brand_mentions_elsewhere']
    assert public_result(r)['status'] == 'uncertain'


def test_catalog_matches_exact_boundary_only(analyzer):
    for site in CATALOG['sites']:
        domain = site['domain']
        assert site['name'] in analyzer.analizar('https://' + domain)['reference']['hostname_matches']
        assert not analyzer.analizar('https://' + domain + '.ejemplo.test')['reference']['hostname_matches']


def test_missing_model_has_no_public_score():
    r = AnalizadorURL('/tmp/no-model-v2.joblib').analizar('https://example.com')
    assert public_result(r)['status'] == 'unavailable'
    assert public_result(r)['percent'] is None


def test_api_exposes_public_view_and_original_score(monkeypatch):
    from app import app
    monkeypatch.delenv('MODEL_PATH', raising=False)
    app.middleware_stack = None
    with TestClient(app) as client:
        r = client.post('/api/analyze', json={'url':'https://www.bancoestado.cl/content/home.html'}).json()
    assert r['public']['status'] == 'uncertain'
    assert r['p_phishing'] is not None
