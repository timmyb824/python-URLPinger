# URL Pinger

## Summary

UrlPinger is a simple python application that "pings" a list of urls and checks the response time and status code. The application reads the list of urls from a [configuration file](configuration.md) and sends HTTP GET requests or pings [using the `ping` command] to each url. Prometheus metrics are exposed for each url including the respons time, total number of pings, total number of succesful pings, total number of failed pings, and the urls status. The application runs in Kubernetes using dex.

## Configuration

The application reads the list of urls from a JSON [configuration file](configuration.md). Each url has a name, URL, and a flag to indicate if the url should be pinged using the `ping` command; otherwise the default is to ping the url using HTTP.

## Metrics

The application exposes the following metrics for each url:

- `url_status`: 1 if the url is up, 0 if the url is down, 2 if the url is in maintenance mode.
- `url_checks`: The total number of pings to the url.
- `url_checks_success_total`: The total number of successful pings to the url.
- `url_checks_failure_total`: The total number of failed pings to the url.
- `url_response_time`: The response time of the url in seconds.

A Grafana dashboard is available to visualize the metrics and includes status, uptime, and response time graphs for each url. The dashboard is available [here]() (TO BE ADDED).
