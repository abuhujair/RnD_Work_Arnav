'''
ENV FLASK_APP=monitor_server.py
CMD flask run -h 0.0.0 -p 6000
'''
# for server 
from flask import Response, Flask, request
import random

import prometheus_client
#  to collect the metric 
from prometheus_client.core import CollectorRegistry
#  differet metric formats 
from prometheus_client import Summary, Counter, Histogram, Gauge
#  to simulate and capture time
import time

app = Flask(__name__)

_INF = float("inf")

#  empty dictionary creation 
metric = {}

#counter metric 
metric['c'] = Counter('python_request_operations_total', 'The total number of processed requests')

# histogram metric
metric['h'] = Histogram('python_request_duration_seconds', 'Histogram for the duration in seconds.', buckets=(1, 2, 5, 6, 10, _INF))

# server calls to generate data .. it can be also read form file or stored at ebuf output 
@app.route("/")
def hello():
    # time calculation 
    start = time.time()

    #incrementing the count metric 
    metric['c'].inc()

    # simulating time to generate metric
    time.sleep(random.randint(0,9)*0.10)

    # time calculation ends
    end = time.time()

    # feed time input to the histogram metric
    metric['h'].observe(end - start)

    return "Hello World"

# default pull route for metric ny prometheus
@app.route("/metrics")
def requests_count():

    # standard code accumualtion as per prometheus style
    res = []
    for k,v in metric.items():
        res.append(prometheus_client.generate_latest(v))
    return Response(res, mimetype="text/plain")

