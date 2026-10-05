from deepcti.judge import perturb as P
from deepcti.judge.prompts import call_ids_in
from deepcti.judge.stats import cluster_bootstrap, cohen_kappa, fleiss_kappa


def test_wrong_version_bumps_major_and_avoids_evidence():
    c = "The installed version of expat on srv-1 is 2.5.0-1+deb12u3."
    assert P.wrong_version(c, "") == "The installed version of expat on srv-1 is 3.5.0-1+deb12u3."
    assert P.wrong_version(c, "x 3.5.0-1+deb12u3 y") == "The installed version of expat on srv-1 is 4.5.0-1+deb12u3."
    assert P.wrong_version("openssh 1:9.2p1-2+deb12u3 installed", "") == "openssh 1:10.2p1-2+deb12u3 installed"
    assert P.wrong_version("CVE-2026-24515 affects srv-app-84251c", "") is None
    assert P.wrong_version("Debian 12 host", "") is None


def test_status_and_polarity():
    assert P.wrong_status("Host srv-1 is not affected by CVE-1.") == "Host srv-1 is affected by CVE-1."
    assert P.wrong_status("Host srv-1 is affected by CVE-1.") == "Host srv-1 is not affected by CVE-1."
    assert P.wrong_status("status not_affected") == "status affected"
    assert P.wrong_status("The fixed version is 2.7.4.") is None
    assert P.wrong_status("Host is within the affected range.") is None
    assert P.flipped_polarity("The vulnerable code is not present on srv-1.") == "The vulnerable code is present on srv-1."
    assert P.flipped_polarity("The tracker does provide a fixed version.") == "The tracker does not provide a fixed version."
    assert P.flipped_polarity("The tracker doesn't list a precondition.") == "The tracker does list a precondition."
    assert P.flipped_polarity("Host srv-1 is not affected.") is None  # status claims go to wrong_status


def test_invented_id_and_citations():
    assert P.invented_id("pkg absent [c002].", ["c001", "c002"]) == "pkg absent [c007]."
    assert P.invented_id("present [c004, c006]", ["c004", "c006"]) == "present [c011, c006]"
    assert P.invented_id("pkg absent.", ["c001"]) == "pkg absent [c006]."
    assert call_ids_in("a [c004, c006] b [pkgdb] c [c004]") == ["c004", "c006"]


def test_kappa_and_bootstrap():
    a = ["s", "s", "n", "n", "s", "c"]
    assert abs(cohen_kappa(a, a) - 1.0) < 1e-9
    assert abs(fleiss_kappa([[3, 0], [0, 3], [3, 0]]) - 1.0) < 1e-9
    import pandas as pd
    df = pd.DataFrame({"cve": ["a", "a", "b", "c"], "num": [1, 1, 0, 1], "den": [1, 1, 1, 1]})
    est, lo, hi = cluster_bootstrap(df, "cve", lambda d: d.num.sum() / d.den.sum(), n=200)
    assert est == 0.75 and lo <= est <= hi


def test_ratio_ci():
    import pandas as pd

    from deepcti.judge.stats import ratio_ci
    df = pd.DataFrame({"cve": ["a", "a", "b", "c"], "num": [1, 1, 0, 1], "den": [1, 1, 1, 1]})
    est, lo, hi = ratio_ci(df, "cve", "num", "den", n=500)
    assert est == 0.75 and 0 <= lo <= est <= hi <= 1
