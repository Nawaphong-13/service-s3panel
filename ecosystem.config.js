module.exports = {
    "apps": [{
        "name": "service-s3-panel",
        "script": "gunicorn -w 2 -b 0.0.0.0:4490 app:app --access-logfile - --error-logfile - --log-level debug",
        "instances": "1",
        "output": "./logs/my-app-out.log",
        "error": "./logs/my-app-error.log"
    }]
}