import cveprey, argparse

parser = argparse.ArgumentParser()

parser.add_argument(
    '-cve',
    required=True,
    metavar='CVE',
    dest='cve',
    help='Holds the CVE Number'
)

args = parser.parse_args()

cve_info = cveprey.CVE(args.cve)
cve_info.get_nvd_data()

adv = cveprey.ciscoAdvisories(cve_info.cve_id, cve_info.nvd_data.adv_links[0])
cvrf = adv.cvrf_contents()
versions = cvrf.affected_versions

print(versions)