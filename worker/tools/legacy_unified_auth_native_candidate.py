"""Verify only the fixed hosted V11 archive before a future native restore."""

import legacy_dynamic_all_candidate as dynamic
import legacy_general_auth_candidate as auth
from legacy_general_auth_native_candidate import TABLE_PINS as AUTH_TABLE_PINS
import legacy_unified_share_native_candidate as unified
import legacy_unified_share_native_fixture as fixture
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


UNIFIED_AUTH_PROFILE = "synthetic-legacy-unified-auth"
UNIFIED_AUTH_ORACLE_SCOPE = unified.UNIFIED_SHARE_ORACLE_SCOPE
ERROR = "The synthetic unified authorization restore candidate could not be confirmed safely."
PACKAGE_LIMITS = unified.PACKAGE_LIMITS
SQL_LIMIT = unified.SQL_LIMIT
ARCHIVE_LIMIT = unified.ARCHIVE_LIMIT
unified_auth_object_limit = unified.unified_share_object_limit


def require(condition):
    native.require(condition, ERROR)


def target_schema_objects(base):
    """Extend only the unbound target's replay and readback schema."""
    require(all(obj.name not in auth.COLUMNS and obj.table not in auth.COLUMNS for obj in base))
    return (*base, *auth.SCHEMA)


def unified_auth_candidate_files(document):
    require(isinstance(document, dict) and native.integer(document.get("version"), 11, 11))
    authorization, source = document.get("generalAuthorization"), document.get("source")
    require(isinstance(authorization, dict) and set(authorization) == {"activationAllowed", "counts", "schemaSha256", "tableSha256"}
            and authorization["activationAllowed"] is False and authorization["schemaSha256"] == native._schema_digest(auth.SCHEMA)
            and isinstance(source, dict))
    counts, table_sha = authorization["counts"], authorization["tableSha256"]
    provenance = source.get("generalAuthorization")
    require(isinstance(counts, dict) and set(counts) == set(fixture.AUTH_COUNTS)
            and all(native.integer(counts[key], value, value) for key, value in fixture.AUTH_COUNTS.items())
            and isinstance(table_sha, dict) and set(table_sha) == set(auth.COLUMNS)
            and all(native.matches(native.DIGEST, value) for value in table_sha.values())
            and isinstance(provenance, dict) and set(provenance) == set(auth.PROVENANCE.values())
            and native.matches(artifact._REVISION, provenance["sourceRevision"])
            and all(native.matches(native.DIGEST, value) for key, value in provenance.items() if key != "sourceRevision")
            and provenance["sourceSha256"] == source.get("sqliteSha256") and source.get("legacyBotId") == dynamic.BOT_ID)
    try:
        return unified._unified_candidate_files(document)
    except (native.RehearsalError, ValueError, TypeError, KeyError):
        raise native.RehearsalError(ERROR) from None


class UnifiedAuthCandidate(unified._UnifiedCandidate):
    profile = UNIFIED_AUTH_PROFILE
    error_message = ERROR
    archive_files = staticmethod(unified_auth_candidate_files)
    expected_nonempty = {**unified.EXPECTED_NONEMPTY,
        auth.INSTALLATION: fixture.AUTH_COUNTS["installations"], auth.PRINCIPALS: fixture.AUTH_COUNTS["principals"],
        auth.GROUPS: fixture.AUTH_COUNTS["groups"],
    }

    @staticmethod
    def _rebuild(root, worker, revision, oracle):
        return fixture.build_unified_auth_fixture(root, worker, revision, oracle=oracle)

    @staticmethod
    def _schema_objects(chain):
        return target_schema_objects(unified._UnifiedCandidate._schema_objects(chain))

    def _check_summary(self, summary):
        super()._check_summary(summary)
        require(self.document["generalAuthorization"]["tableSha256"]
                == {table: summary["tableSha256"][table] for table in auth.COLUMNS})

    def _check_rows(self, db, chain):
        super()._check_rows(db, chain)
        provenance = self.document["source"]["generalAuthorization"]
        installation = (dynamic.BOT_ID, *(provenance[key] for key in auth.PROVENANCE.values()), "explicit", "denied")
        overrides = {str(actor): (allowed, created, updated) for actor, allowed, created, updated in fixture.AUTH_OVERRIDES}
        principals = [(dynamic.BOT_ID, dynamic.OWNER, 1, 0, *overrides[dynamic.OWNER]),
                      (dynamic.BOT_ID, dynamic.TEMP_ONLY_OWNER, 0, 0, *overrides[dynamic.TEMP_ONLY_OWNER]),
                      (dynamic.BOT_ID, dynamic.FOREIGN_OWNER, 0, 1, None, None, None)]
        groups = [(dynamic.BOT_ID, group) for group in fixture.AUTH_GROUPS]
        require(db.execute(f"SELECT * FROM {auth.INSTALLATION}").fetchall() == [installation]
                and db.execute(f"SELECT * FROM {auth.PRINCIPALS} ORDER BY user_id").fetchall() == principals
                and db.execute(f"SELECT * FROM {auth.GROUPS} ORDER BY CAST(chat_id AS INTEGER)").fetchall() == groups)

    def pin(self):
        pin = super().pin()
        pin["unifiedAuthOracleManifestSha256"] = pin.pop("unifiedShareOracleManifestSha256")
        section = self.document["generalAuthorization"]
        source = self.document["source"]["generalAuthorization"]
        return {**pin, "candidateSchemaSha256": section["schemaSha256"],
                "generalAuthSourceSha256": source["sourceSha256"], "previewManifestSha256": source["previewManifestSha256"],
                **{key: section["tableSha256"][table] for table, key in AUTH_TABLE_PINS.items()}}

    def native_evidence(self, summary):
        common = super().native_evidence(summary)
        pin = self.pin()
        counts = fixture.AUTH_COUNTS
        return {**common, "activationAllowed": False, "verifiedGeneralAuthInstallationCount": counts["installations"],
                "verifiedGeneralAuthPrincipalCount": counts["principals"], "verifiedGeneralAuthGroupCount": counts["groups"],
                "verifiedGeneralAuthOverrideCount": counts["overrides"],
                **{key: pin[key] for key in ("candidateSchemaSha256", "generalAuthSourceSha256", "previewManifestSha256",
                                              *AUTH_TABLE_PINS.values())}}
