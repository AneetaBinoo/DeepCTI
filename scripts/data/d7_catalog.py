"""Static catalog for the D7 builder: aliases, decoys, siblings, fillers, application names, banners.

Every entry here is a modelling choice (documented in data/d7/BUILD_REPORT.md); versions are never chosen
here — they come from the mirrored upstream version lists.
"""

from __future__ import annotations

# ----------------------------------------------------------------------------------------------- PyPI
# name -> display, decoy (independent PyPI project whose name/vendor overlaps; None = no V6),
#         vendorable (V7: copy vendored into another distribution's _vendor/ tree), server banner template
PYPI = {
    "werkzeug": {"display": "Werkzeug", "decoy": "itsdangerous", "vendorable": False,
                 "banner": "Werkzeug/{v} Python/3.10.12"},
    "aiohttp": {"display": "aiohttp", "decoy": "aiosignal", "vendorable": False,
                "banner": "Python/3.10 aiohttp/{v}"},
    "waitress": {"display": "waitress", "decoy": "hupper", "vendorable": False, "banner": "waitress"},
    "starlette": {"display": "Starlette", "decoy": "hypercorn", "vendorable": False, "banner": "uvicorn"},
    "mlflow": {"display": "MLflow", "decoy": None, "vendorable": False, "banner": ""},
    "django": {"display": "Django", "decoy": "django-environ", "vendorable": False, "banner": ""},
    "urllib3": {"display": "urllib3", "decoy": "types-urllib3", "vendorable": True, "banner": ""},
    "requests": {"display": "Requests", "decoy": "types-requests", "vendorable": True, "banner": ""},
    "jinja2": {"display": "Jinja2", "decoy": "markupsafe", "vendorable": False, "banner": ""},
    "gunicorn": {"display": "Gunicorn", "decoy": "uvicorn", "vendorable": False, "banner": "gunicorn"},
    "cryptography": {"display": "cryptography", "decoy": "pycryptodome", "vendorable": False, "banner": ""},
    "setuptools": {"display": "setuptools", "decoy": "wheel", "vendorable": False, "banner": ""},
    "pyyaml": {"display": "PyYAML", "decoy": "ruamel.yaml", "vendorable": False, "banner": ""},
    "tornado": {"display": "Tornado", "decoy": None, "vendorable": False, "banner": "TornadoServer/{v}"},
    "flask": {"display": "Flask", "decoy": "blinker", "vendorable": False, "banner": ""},
    "idna": {"display": "idna", "decoy": None, "vendorable": True, "banner": ""},
    "pillow": {"display": "Pillow", "decoy": "pilkit", "vendorable": False, "banner": ""},
    "python-multipart": {"display": "python-multipart", "decoy": "multipart", "vendorable": False, "banner": ""},
    "pyjwt": {"display": "PyJWT", "decoy": "jwt", "vendorable": False, "banner": ""},
    "jupyter-server": {"display": "Jupyter Server", "decoy": "jupyter-client", "vendorable": False,
                       "banner": "TornadoServer/6.4.1"},
}
# distribution that vendors a copy (pip-style _vendor tree) for V7
PYPI_VENDOR_HOST = {"urllib3": "pip", "requests": "pip", "idna": "pip", "setuptools": "pkg_resources_host"}
# neutral fillers (no known CVEs at the pinned versions) present in every application venv
PYPI_FILLERS = [("six", "1.16.0"), ("python-dateutil", "2.9.0.post0"), ("pytz", "2024.1")]
PYPI_APP_POOL = ["orders-api", "catalog-svc", "notify-worker", "pricing-api", "search-svc", "intake-web",
                 "metrics-api", "docs-portal"]

# ---------------------------------------------------------------------------------------------- Maven
MAVEN = {
    "org.apache.logging.log4j:log4j-core": {"title": "Apache Log4j Core", "vendor": "The Apache Software Foundation",
                                            "aliases": ["Log4j", "Apache Log4j", "Log4j 2"],
                                            "decoy": "org.apache.logging.log4j:log4j-api",
                                            "siblings": ["org.apache.logging.log4j:log4j-api"]},
    "log4j:log4j": {"title": "log4j", "vendor": "Apache Software Foundation", "aliases": ["Log4j 1.x", "Apache Log4j 1"],
                    "decoy": "org.slf4j:log4j-over-slf4j", "siblings": []},
    "org.springframework:spring-beans": {"title": "spring-beans", "vendor": "Spring",
                                         "aliases": ["Spring Framework", "Spring Beans"],
                                         "decoy": "org.springframework.security:spring-security-crypto",
                                         "siblings": ["org.springframework:spring-core"]},
    "org.springframework:spring-core": {"title": "spring-core", "vendor": "Spring",
                                        "aliases": ["Spring Framework", "Spring Core"],
                                        "decoy": "org.springframework.security:spring-security-crypto",
                                        "siblings": []},
    "com.h2database:h2": {"title": "H2 Database Engine", "vendor": "H2 Group", "aliases": ["H2", "H2 Database"],
                          "decoy": "com.h2database:h2-mvstore", "siblings": []},
    "org.apache.shiro:shiro-core": {"title": "Apache Shiro :: Core", "vendor": "The Apache Software Foundation",
                                    "aliases": ["Apache Shiro", "Shiro"],
                                    "decoy": "org.apache.shiro:shiro-crypto-cipher", "siblings": []},
    "org.apache.struts:struts2-core": {"title": "Struts 2 Core", "vendor": "Apache Software Foundation",
                                       "aliases": ["Apache Struts", "Struts 2", "Struts2"],
                                       "decoy": "org.apache.struts:struts-core", "siblings": []},
    "org.postgresql:postgresql": {"title": "PostgreSQL JDBC Driver", "vendor": "PostgreSQL Global Development Group",
                                  "aliases": ["pgjdbc", "PostgreSQL JDBC Driver"],
                                  "decoy": "com.impossibl.pgjdbc-ng:pgjdbc-ng", "siblings": []},
    "ch.qos.logback:logback-classic": {"title": "Logback Classic Module", "vendor": "QOS.ch",
                                       "aliases": ["logback", "Logback"],
                                       "decoy": "org.slf4j:slf4j-simple", "siblings": ["ch.qos.logback:logback-core"]},
    "ch.qos.logback:logback-core": {"title": "Logback Core Module", "vendor": "QOS.ch", "aliases": ["logback", "Logback"],
                                    "decoy": "ch.qos.reload4j:reload4j", "siblings": []},
    "org.apache.activemq:activemq-client": {"title": "ActiveMQ :: Client", "vendor": "The Apache Software Foundation",
                                            "aliases": ["Apache ActiveMQ", "ActiveMQ", "OpenWire"],
                                            "decoy": "org.apache.activemq:artemis-jms-client", "siblings": []},
    "org.springframework.cloud:spring-cloud-function-context": {
        "title": "spring-cloud-function-context", "vendor": "Pivotal Software, Inc.",
        "aliases": ["Spring Cloud Function"], "decoy": "org.springframework.cloud:spring-cloud-commons", "siblings": []},
    "com.thoughtworks.xstream:xstream": {"title": "XStream Core", "vendor": "XStream", "aliases": ["XStream"],
                                         "decoy": "com.thoughtworks.qdox:qdox", "siblings": []},
    "org.apache.commons:commons-text": {"title": "Apache Commons Text", "vendor": "The Apache Software Foundation",
                                        "aliases": ["Commons Text", "Apache Commons Text"],
                                        "decoy": "org.apache.commons:commons-lang3", "siblings": []},
    "org.yaml:snakeyaml": {"title": "SnakeYAML", "vendor": "snakeyaml", "aliases": ["SnakeYAML"],
                           "decoy": "org.snakeyaml:snakeyaml-engine", "siblings": []},
    "commons-fileupload:commons-fileupload": {"title": "Apache Commons FileUpload",
                                              "vendor": "The Apache Software Foundation",
                                              "aliases": ["Commons FileUpload", "Apache Commons FileUpload"],
                                              "decoy": "commons-io:commons-io", "siblings": []},
    "com.fasterxml.jackson.core:jackson-databind": {"title": "jackson-databind", "vendor": "FasterXML",
                                                    "aliases": ["Jackson", "jackson-databind", "Jackson Databind"],
                                                    "decoy": "com.fasterxml.jackson.core:jackson-core",
                                                    "siblings": []},
    "org.apache.tomcat.embed:tomcat-embed-core": {"title": "tomcat-embed-core", "vendor": "Apache Software Foundation",
                                                  "aliases": ["Apache Tomcat", "Tomcat", "embedded Tomcat"],
                                                  "decoy": "org.apache.tomcat.embed:tomcat-embed-el", "siblings": []},
    "io.netty:netty-codec-http": {"title": "Netty/Codec/HTTP", "vendor": "The Netty Project",
                                  "aliases": ["Netty", "netty-codec-http"], "decoy": "io.netty:netty-buffer",
                                  "siblings": []},
    "io.netty:netty-codec-http2": {"title": "Netty/Codec/HTTP2", "vendor": "The Netty Project",
                                   "aliases": ["Netty", "netty-codec-http2"], "decoy": "io.netty:netty-common",
                                   "siblings": []},
    "org.bouncycastle:bcprov-jdk18on": {"title": "bcprov", "vendor": "BouncyCastle.org",
                                        "aliases": ["Bouncy Castle", "BouncyCastle", "bcprov"], "decoy": None,
                                        "siblings": []},
    "org.eclipse.jetty:jetty-server": {"title": "Jetty :: Server Core", "vendor": "Eclipse Jetty Project",
                                       "aliases": ["Eclipse Jetty", "Jetty"], "decoy": "org.eclipse.jetty:jetty-util",
                                       "siblings": []},
}
MAVEN_FILLERS = [("org.slf4j:slf4j-api", "2.0.13"), ("commons-codec:commons-codec", "1.17.0")]
MAVEN_APP_POOL = ["order-service", "payments-api", "crm-backend", "shipping-svc", "hr-portal", "warehouse-api",
                  "analytics-svc", "quote-engine"]
# V7 host application (fat jar that bundles the vulnerable library under BOOT-INF/lib/)
MAVEN_FATJAR_POOL = ["dispatch-bundle", "tenant-manager", "pricing-batch", "report-runner"]

# --------------------------------------------------------------------------------------------- vendor
VENDOR = {
    "tomcat": {"display": "Apache Tomcat", "aliases": ["Apache Tomcat", "Tomcat", "tomcat"], "dir": "opt/tomcat",
               "decoy": "httpd", "banner": "Apache Tomcat/{v}", "unit": "tomcat.service",
               "cmd": "/usr/lib/jvm/java-17-openjdk-amd64/bin/java -Dcatalina.base=/opt/tomcat "
                      "-Dcatalina.home=/opt/tomcat org.apache.catalina.startup.Bootstrap start"},
    "httpd": {"display": "Apache HTTP Server", "aliases": ["Apache HTTP Server", "Apache httpd", "httpd", "Apache"],
              "dir": "opt/httpd", "decoy": "tomcat", "banner": "Apache/{v} (Unix)", "unit": "httpd.service",
              "cmd": "/opt/httpd/bin/httpd -k start"},
    "jenkins": {"display": "Jenkins", "aliases": ["Jenkins", "Jenkins core", "jenkins"], "dir": "opt/jenkins",
                "decoy": "jenkins-agent", "banner": "X-Jenkins: {v}", "unit": "jenkins.service",
                "cmd": "/usr/bin/java -Djava.awt.headless=true -jar /opt/jenkins/jenkins.war --httpPort=8080"},
    "roundcube": {"display": "Roundcube Webmail", "aliases": ["Roundcube", "Roundcube Webmail", "roundcubemail"],
                  "dir": "opt/roundcube", "decoy": "rcmcarddav", "banner": "Roundcube Webmail {v}",
                  "unit": "php8.1-fpm.service", "cmd": "php-fpm: pool roundcube"},
    "gitlab": {"display": "GitLab", "aliases": ["GitLab", "GitLab EE", "GitLab CE/EE", "gitlab-ee"],
               "dir": "opt/gitlab", "decoy": "gitlab-runner", "banner": "GitLab Enterprise Edition {v}-ee",
               "unit": "gitlab-runsvdir.service", "cmd": "puma 6.4.0 (unix:///var/opt/gitlab/gitlab-rails/sockets/gitlab.socket,tcp://127.0.0.1:8080) [gitlab-puma-worker]"},
}
# decoy-only vendor products (version evidence written like a real product, never in any selected CVE)
VENDOR_DECOYS = {
    "jenkins-agent": {"display": "Jenkins inbound agent (remoting)", "dir": "opt/jenkins-agent",
                      "version": "3256.3258.v858f3c9a_f69d"},
    "rcmcarddav": {"display": "RCMCardDAV plugin for Roundcube", "dir": "opt/rcmcarddav", "version": "5.1.0"},
    "gitlab-runner": {"display": "GitLab Runner", "dir": "opt/gitlab-runner", "version": "17.11.0"},
}
