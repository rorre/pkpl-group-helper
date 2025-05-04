from threading import Lock


ALERTS: dict[str, list[str]] = {}

mutex = Lock()


def alert(npm: str, message: str):
    with mutex:
        if npm not in ALERTS:
            ALERTS[npm] = []
        ALERTS[npm].append(message)
        return ALERTS[npm]


def get_alerts(npm: str):
    with mutex:
        alerts = ALERTS.get(npm, [])
        ALERTS[npm] = []
        return alerts
