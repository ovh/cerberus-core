

from datetime import datetime

import rq_dashboard

from flask import render_template_string

from ...utils.text import dehtmlify

settings = rq_dashboard.default_settings
blueprint = rq_dashboard.blueprint

template = """
<!DOCTYPE html>
<html>
<head>
<style>
table {
    font-family: arial, sans-serif;
    border-collapse: collapse;
    width: 100%;
}

td, th {
    border: 1px solid #dddddd;
    text-align: left;
    padding: 8px;
}

tr:nth-child(even) {
    background-color: #dddddd;
}
</style>
</head>
<body>

<table>
  <tr>
    <td>Date</td>
    <td>{{ date }}</td>
  </tr>
  <tr>
    <td>From</td>
    <td>{{ provider }}</td>
  </tr>
  <tr>
    <td>To</td>
    <td>{{ recipients }}</td>
  </tr>
  <tr>
    <td>Category</td>
    <td>{{ category }}</td>
  </tr>
  <tr>
    <td>Applied parsing template</td>
    <td>{{ template }}</td>
  </tr>
  <tr>
    <td>Subject</td>
    <td>{{ subject }}</td>
  </tr>
  <tr>
    <td>Body</td>
    {% autoescape false %}
    <td><pre>{{ body }}</pre></td>
    {% endautoescape %}
  </tr>
  <tr>
    <td>IPs</td>
    <td>{{ ips }}</td>
  </tr>
  <tr>
    <td>URLs</td>
    <td>{{ urls }}</td>
  </tr>
  <tr>
    <td>FQDN</td>
    <td>{{ fqdn }}</td>
  </tr>
</table>

</body>
</html>
"""


# Add custom route
@blueprint.route('/job/<job_id>/parsed-email', methods=['GET'])
def get_parsed_email(job_id):

    from rq.job import Job
    from ..parsers import Parser

    job = Job.fetch(job_id)
    if not job:
        return {"message": "Invalid job ID"}

    raw = job.kwargs.get('email_content')
    if not raw:
        return {"message": "Unable to get raw email"}

    p = Parser()
    parsed = p.parse_from_email(raw)

    return render_template_string(
        template,
        date=datetime.fromtimestamp(parsed.date),
        provider=parsed.provider,
        recipients=parsed.recipients,
        category=parsed.category,
        template=parsed.applied_template,
        ips=parsed.ips,
        urls=parsed.urls,
        fqdn=parsed.fqdn,
        subject=parsed.subject,
        body=dehtmlify(parsed.body)
    )
