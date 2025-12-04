import os
from typing import Any, Dict, List, Optional

class ElasticClient:
    def __init__(self) -> None:
        self.url = os.getenv("ELASTICSEARCH_URL")
        self.index = os.getenv("ELASTIC_INDEX", "http_logs")
        self.username = os.getenv("ELASTIC_USERNAME")
        self.password = os.getenv("ELASTIC_PASSWORD")
        verify_env = os.getenv("ELASTIC_VERIFY_CERTS", "true").lower()
        self.verify_certs = verify_env in ("1", "true", "yes")

        self._client = None
        self._helpers = None
        self.available = False
        if self.url:
            try:
                from elasticsearch import Elasticsearch, helpers
                auth = None
                if self.username and self.password:
                    auth = (self.username, self.password)
                self._client = Elasticsearch(self.url, basic_auth=auth, verify_certs=self.verify_certs)
                self._helpers = helpers
                self.available = True
            except Exception:
                self.available = False

    def ensure_index(self) -> None:
        if not self.available:
            return
        try:
            exists = self._client.indices.exists(index=self.index)
            if not exists:
                self._client.indices.create(index=self.index, settings={"number_of_shards": 1, "number_of_replicas": 0})
        except Exception:
            pass

    def index_documents(self, docs: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not self.available:
            return {"success": False, "indexed": 0, "index": self.index}
        self.ensure_index()
        actions = [{"_index": self.index, "_source": d} for d in docs]
        try:
            result = self._helpers.bulk(self._client, actions, stats_only=True)
            return {"success": True, "indexed": int(result[0]), "index": self.index}
        except Exception:
            return {"success": False, "indexed": 0, "index": self.index}
