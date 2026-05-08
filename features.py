<!DOCTYPE html>
<html>
<head>

<title>Result</title>

<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">

<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&display=swap" rel="stylesheet">

</head>

<body>

<header>
<div>SecureGuard</div>
<div class="nav-links">
  <a href="/home">Home</a>
  <a href="/history">History</a>
  <a href="/logout">Logout</a>
</div>
</header>

<section class="hero">

<h1>Scan Result</h1>

<div class="main-card">

<p><b>URL:</b> {{url}}</p>

{% if not reachable %}
<div class="unreachable">
  ⚠️ This website is currently unreachable or down. We analyzed its structure instead.
</div>
{% endif %}

{% if "Safe" in prediction %}

<div class="safe">
{{prediction}}
</div>

{% else %}

<div class="phishing">
{{prediction}}
</div>

{% endif %}

{% if details %}
<div class="details-box">
  <h3>URL Threat Breakdown</h3>
  <ul>
  {% for key, value in details.items() %}
    <li><b>{{key}}:</b> {{value}}</li>
  {% endfor %}
  </ul>
</div>
{% endif %}

<br>

<a href="/home">
<button>Check Another URL</button>
</a>

</div>

</section>

<footer>
© 2026 Phishing URL Detection Project
</footer>

</body>
</html>