from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import XsUri, ExternalReferenceType
from cyclonedx.model.bom import Bom, OrganizationalEntity
from cyclonedx.model.component import Component, ComponentType, ExternalReference
from cyclonedx.model.impact_analysis import ImpactAnalysisAffectedStatus
from cyclonedx.model.vulnerability import (
    Vulnerability,
    VulnerabilitySource,
    VulnerabilityScoreSource,
    VulnerabilityRating,
    VulnerabilitySeverity,
    BomTarget,
    BomTargetVersionRange,
)
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.schema import SchemaVersion
from cyclonedx.output.json import JsonV1Dot4
from datetime import datetime

"""
utilities to create the CycloneDX BOM objects and serialize it to JSON
"""


def get_base_bom() -> Bom:
    lc_factory = LicenseFactory()
    bom = Bom()
    bom.metadata.component = root_component = Component(
        name="Eclipse Temurin",
        type=ComponentType.APPLICATION,
        licenses=[lc_factory.make_from_string("GPL-2.0 WITH Classpath-exception-2.0")],
        bom_ref="temurin-vdr",
        supplier=OrganizationalEntity(
            name="Eclipse Foundation",
            urls=[XsUri("https://www.eclipse.org/org/foundation/")],
        ),
        external_references=[
            ExternalReference(
                type=ExternalReferenceType.DISTRIBUTION,
                url=XsUri("http://www.adoptium.net"),
            )
        ],
    )
    return bom


def serialize_to_json(bom: Bom) -> str:
    my_json_outputter = JsonV1Dot4(bom)
    serialized_json = my_json_outputter.output_as_string(indent=2)
    print("\n\n\n")
    print(serialized_json)
    validate_bom(serialized_json)
    return serialized_json


def validate_bom(bom_str: str):
    # todo: should we fail the build if this fails?
    my_json_validator = JsonStrictValidator(SchemaVersion.V1_6)
    try:
        validation_errors = my_json_validator.validate_str(bom_str)
        if validation_errors:
            print("JSON invalid", "ValidationError:", repr(validation_errors), sep="\n")
        else:
            print("JSON valid")
    except MissingOptionalDependencyException as error:
        print("JSON-validation was skipped due to", error)


def sbom_creation_test():
    # based on sample code from https://cyclonedx-python-library.readthedocs.io/en/latest/examples.html
    lc_factory = LicenseFactory()
    bom = Bom()
    bom.metadata.component = root_component = Component(
        name="Eclipse Temurin",
        type=ComponentType.APPLICATION,
        licenses=[lc_factory.make_from_string("GPL v2")],
        bom_ref="temurin-vdr",
    )

    vuln1 = Vulnerability(
        id="CVE-2-23-25193",
        source=VulnerabilitySource(
            name="NVD", url="https://nvd.nist.gov/vuln/detail/CVE-2023-25193"
        ),
        published=datetime.strptime("2023-02-04T20:15:08.027", "%Y-%m-%dT%H:%M:%S.%f"),
        updated=datetime.strptime("2023-07-25T15:15:13.163", "%Y-%m-%dT%H:%M:%S.%f"),
        description="hb-ot-layout-gsubgpos.hh in HarfBuzz through 6.0.0 allows attackers to trigger O(n^2) growth via consecutive marks during the process of looking back for base glyphs when attaching marks.",
        recommendation="Upgrade to the latest version of Eclipse Temurin.",
    )

    rating1 = VulnerabilityRating(
        source=VulnerabilitySource(
            url="https://openjdk.org/groups/vulnerability/advisories", name="OJVG"
        ),
        score=3.7,
        severity=VulnerabilitySeverity.LOW,
        method=VulnerabilityScoreSource.CVSS_V3_1,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    )
    vuln1.ratings.add(rating1)
    bom.vulnerabilities.add(vuln1)
    affects1_range = [
        BomTargetVersionRange(
            range="vers:semver/<=1.8.0.update_382|<=11.0.20|<=17.0.8|<=20.0.2",
            status=ImpactAnalysisAffectedStatus.AFFECTED,
        )
    ]
    affects1 = BomTarget(ref="temurin-vdr")
    vuln1.affects.add(affects1)

    my_json_outputter = JsonV1Dot4(bom)
    serialized_json = my_json_outputter.output_as_string(indent=2)
    print("\n\n\n")
    print(serialized_json)


# validate_bom(open("vdr.json","r").read())
