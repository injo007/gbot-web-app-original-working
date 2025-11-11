from flask import Blueprint, jsonify
from namecheap_client import NamecheapClient, NamecheapAPIError

dns_bp = Blueprint("dns", __name__, url_prefix="/api/dns")

@dns_bp.route("/namecheap/domains", methods=["GET"])
def list_namecheap_domains():
    try:
        client = NamecheapClient()
        domains = client.get_domains()
        return jsonify({
            "success": True,
            "domains": domains
        }), 200
    except NamecheapAPIError as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "code": getattr(e, "code", None)
        }), 400
    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Unexpected server error."
        }), 500
