import queue
import threading
import time

from engines import (
    abuseipdb, abusix, alienvault, chrome_extension, criminalip, crowdstrike, crtsh,
    github, google, google_dns, google_safe_browsing, hudsonrock, ioc_one, ipinfo,
    ipquery, microsoft_defender_for_endpoint, misp, opencti, phishtank, rdap,
    reverse_dns, shodan, spur_us_free, threatfox, urlscan, virustotal, webscout,
)
from models.analysis_result import AnalysisResult
from utils.config import Secrets, get_config
from utils.database import get_analysis_result, save_analysis_result
from utils.utils import is_bogon

secrets: Secrets = get_config()

PROXIES: dict[str, str] = {"http": secrets.proxy_url, "https": secrets.proxy_url}
SSL_VERIFY: bool = secrets.ssl_verify


def safe_query(query_func, *args, **kwargs):
    try:
        res = query_func(*args, **kwargs)
        return res if res is not None else "No se encontraron resultados"
    except Exception as e:
        return {"error": str(e)}


def perform_analysis(app, observables, selected_engines, analysis_id):
    with app.app_context():
        start_time = time.time()

        analysis_result = AnalysisResult(
            id=analysis_id,
            results=[],
            start_time=start_time,
            end_time=None,
            start_time_string=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
            end_time_string="",
            analysis_duration_string="",
            analysis_duration=0,
            selected_engines=selected_engines,
            in_progress=True,
        )
        save_analysis_result(analysis_result)

        result_queue = queue.Queue()
        threads = [
            threading.Thread(
                target=analyze_observable,
                args=(observable, index, selected_engines, result_queue),
            )
            for index, observable in enumerate(observables)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        results = collect_results_from_queue(result_queue, len(observables))
        update_analysis_metadata(analysis_id, start_time, selected_engines, results)


def analyze_observable(observable, index, selected_engines, result_queue):
    result = initialize_result(observable)
    result = perform_engine_queries(observable, selected_engines, result)
    result_queue.put((index, result))


def initialize_result(observable):
    return {
        "observable": observable["value"],
        "type": observable["type"],
        "reversed_success": False,
    }


def perform_engine_queries(observable, selected_engines, result):
    if observable["type"] in ["IPv4", "IPv6"] and is_bogon(observable["value"]):
        observable["type"] = "BOGON"

    if "urlscan" in selected_engines:
        result["urlscan"] = safe_query(urlscan.query_urlscan, observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "crtsh" in selected_engines:
        result["crtsh"] = safe_query(crtsh.query_crtsh, observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "ioc_one_html" in selected_engines:
        result["ioc_one_html"] = safe_query(ioc_one.query_ioc_one_html, observable["value"], PROXIES, SSL_VERIFY)

    if "ioc_one_pdf" in selected_engines:
        result["ioc_one_pdf"] = safe_query(ioc_one.query_ioc_one_pdf, observable["value"], PROXIES, SSL_VERIFY)

    if "google" in selected_engines:
        result["google"] = safe_query(google.query_google, observable["value"], PROXIES, SSL_VERIFY)

    if "github" in selected_engines:
        result["github"] = safe_query(github.query_github, observable["value"], PROXIES, SSL_VERIFY)

    if "rdap" in selected_engines:
        result["rdap"] = safe_query(rdap.query_openrdap, observable["value"], observable["type"], PROXIES, SSL_VERIFY)

    if "mde" in selected_engines:
        result["mde"] = safe_query(
            microsoft_defender_for_endpoint.query_microsoft_defender_for_endpoint,
            observable["value"], observable["type"],
            secrets.mde_tenant_id, secrets.mde_client_id, secrets.mde_client_secret,
            PROXIES, SSL_VERIFY
        )

    if "crowdstrike" in selected_engines:
        result["crowdstrike"] = safe_query(
            crowdstrike.query_crowdstrike,
            observable["value"], observable["type"],
            secrets.crowdstrike_client_id, secrets.crowdstrike_client_secret,
            secrets.crowdstrike_falcon_base_url, SSL_VERIFY, PROXIES
        )

    if "opencti" in selected_engines:
        result["opencti"] = safe_query(
            opencti.query_opencti,
            observable["value"], secrets.opencti_api_key, secrets.opencti_url, PROXIES, SSL_VERIFY
        )

    if "threatfox" in selected_engines:
        result["threatfox"] = safe_query(
            threatfox.query_threatfox,
            observable["value"], observable["type"], secrets.threatfox, PROXIES, SSL_VERIFY
        )

    if "virustotal" in selected_engines:
        result["virustotal"] = safe_query(
            virustotal.query_virustotal,
            observable["value"], observable["type"], secrets.virustotal, PROXIES, SSL_VERIFY
        )

    if "alienvault" in selected_engines:
        result["alienvault"] = safe_query(
            alienvault.query_alienvault,
            observable["value"], observable["type"], PROXIES, SSL_VERIFY, secrets.alienvault
        )

    if "misp" in selected_engines:
        result["misp"] = safe_query(
            misp.query_misp,
            observable["value"], observable["type"],
            PROXIES, SSL_VERIFY, secrets.misp_api_key, secrets.misp_url
        )

    if "google_safe_browsing" in selected_engines:
        result["google_safe_browsing"] = safe_query(
            google_safe_browsing.query_google_safe_browsing,
            observable["value"], observable["type"], secrets.google_safe_browsing, PROXIES, SSL_VERIFY
        )

    if "phishtank" in selected_engines:
        result["phishtank"] = safe_query(
            phishtank.query_phishtank,
            observable["value"], observable["type"], PROXIES, SSL_VERIFY
        )

    if "criminalip" in selected_engines:
        result["criminalip"] = safe_query(
            criminalip.run_criminal_ip_analysis,
            observable["value"], PROXIES, SSL_VERIFY
        )

    if "hudsonrock" in selected_engines:
        result["hudsonrock"] = safe_query(
            hudsonrock.query_hudsonrock,
            observable["value"], observable["type"], PROXIES, SSL_VERIFY
        )

    if "google_dns" in selected_engines:
        result["google_dns"] = safe_query(
            google_dns.query_google_dns,
            observable["value"], observable["type"], PROXIES, SSL_VERIFY
        )

    if "reverse_dns" in selected_engines:
        reverse_dns_result = safe_query(
            reverse_dns.reverse_dns,
            observable["value"], observable["type"]
        )
        result["reverse_dns"] = reverse_dns_result
        if isinstance(reverse_dns_result, dict) and reverse_dns_result.get("reverse_dns"):
            result["reversed_success"] = True
            if observable["type"] in ["FQDN", "URL"]:
                observable["type"] = "IPv4"
                observable["value"] = reverse_dns_result["reverse_dns"][0]

    if "ipquery" in selected_engines:
        result["ipquery"] = safe_query(ipquery.query_ipquery, observable["value"], PROXIES, SSL_VERIFY)

    if "ipinfo" in selected_engines:
        result["ipinfo"] = safe_query(ipinfo.query_ipinfo, observable["value"], secrets.ipinfo, PROXIES, SSL_VERIFY)

    if "abuseipdb" in selected_engines:
        result["abuseipdb"] = safe_query(abuseipdb.query_abuseipdb, observable["value"], secrets.abuseipdb, PROXIES, SSL_VERIFY)

    if "spur" in selected_engines:
        result["spur"] = safe_query(spur_us_free.get_spur, observable["value"], PROXIES, SSL_VERIFY)

    if "webscout" in selected_engines:
        result["webscout"] = safe_query(webscout.query_webscout, observable["value"], secrets.webscout, PROXIES, SSL_VERIFY)

    if "shodan" in selected_engines:
        result["shodan"] = safe_query(shodan.query_shodan, observable["value"], secrets.shodan, PROXIES, SSL_VERIFY)

    if "abusix" in selected_engines:
        result["abusix"] = safe_query(abusix.query_abusix, observable["value"])

    if observable["type"] == "CHROME_EXTENSION":
        result["extension"] = safe_query(chrome_extension.get_name_from_id, observable["value"], PROXIES, SSL_VERIFY)

    return result


def collect_results_from_queue(result_queue, num_observables):
    results = [None] * num_observables
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result
    return results


def check_analysis_in_progress(analysis_id):
    analysis_result = get_analysis_result(analysis_id)
    return analysis_result.in_progress if analysis_result else False


def update_analysis_metadata(analysis_id, start_time, selected_engines, results):
    analysis_result = get_analysis_result(analysis_id)
    if analysis_result:
        end_time = time.time()
        analysis_result.end_time = end_time
        analysis_result.end_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
        analysis_result.analysis_duration = end_time - start_time
        analysis_result.analysis_duration_string = (
            f"{int((end_time - start_time) // 60)} minutes, {(end_time - start_time) % 60:.2f} seconds"
        )
        ##analysis_result.results = results
        grouped_results = {
            result["observable"]: {k: v for k, v in result.items() if k != "observable" and k != "type"}
            for result in results
        }
        analysis_result.results = grouped_results
        analysis_result.in_progress = False
        save_analysis_result(analysis_result)
