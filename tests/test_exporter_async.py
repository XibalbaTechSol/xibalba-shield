from shield.integrity_exporter.exporter import IntegrityExporter


def test_async_worker_uses_flat_commitment_invocation_id():
    calls = []

    class _Queue:
        def __init__(self):
            self.items = [{"invocation_id": "inv-123"}]

        def get(self):
            if self.items:
                return self.items.pop(0)
            raise KeyboardInterrupt

        def task_done(self):
            pass

    exporter = object.__new__(IntegrityExporter)
    exporter._decision_queue = _Queue()
    exporter._submit_commitment = lambda commitment, invocation_id, event_id: calls.append(
        (commitment, invocation_id, event_id)
    )
    try:
        exporter._decision_export_loop()
    except KeyboardInterrupt:
        pass
    assert calls == [({"invocation_id": "inv-123"}, "inv-123", "")]
