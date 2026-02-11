import tempfile
import unittest
from pathlib import Path

import whiteswan_governance_kernel_v3_4 as ws


class WhiteSwanKernelTests(unittest.TestCase):
    def test_import_and_backend(self):
        self.assertIn(ws.CRYPTO_BACKEND, {"pynacl", "hmac-sha256-sim"})
        self.assertTrue(ws.DEFAULT_ALGORITHM)

    def test_issue_and_authorize_allow(self):
        with tempfile.TemporaryDirectory() as td:
            db_file = str(Path(td) / "kernel.db")
            key_file = str(Path(td) / "kernel.key")

            vault = ws.GuardianVaultX(seal_interval=1)
            gov = ws.Governor(vault=vault, db_file=db_file, key_file=key_file)

            op = ws.OperatorIdentity.generate("Alice", "operator")
            gov.register_operator(op, {ws.ActionScope.SENSING})
            sid = gov.create_session(op)

            nonce = ws.generate_nonce()
            gov.issue(op, sid, ws.ActionScope.SENSING, nonce)

            mgi = ws.MGI(gov)
            env = mgi.authorize(ws.ActionScope.SENSING, nonce)

            self.assertEqual(env["outcome"], "ALLOW")
            self.assertEqual(env["scope"], ws.ActionScope.SENSING.value)
            self.assertEqual(env["issuers"], ["Alice"])

            replay = gov.replay_decisions(ws.ActionScope.SENSING, nonce)
            self.assertTrue(any(d["outcome"] == "ALLOW" for d in replay))
            gov.close()

    def test_t3_requires_model_context(self):
        with tempfile.TemporaryDirectory() as td:
            db_file = str(Path(td) / "kernel.db")
            key_file = str(Path(td) / "kernel.key")

            vault = ws.GuardianVaultX()
            gov = ws.Governor(vault=vault, db_file=db_file, key_file=key_file)

            op = ws.OperatorIdentity.generate("Bob", "clinician")
            gov.register_operator(op, {ws.ActionScope.MEDICAL_INTERVENTION})
            sid = gov.create_session(op)
            nonce = ws.generate_nonce()

            with self.assertRaises(ws.OperatorNotAuthorizedError):
                gov.issue(op, sid, ws.ActionScope.MEDICAL_INTERVENTION, nonce)

            gov.close()


if __name__ == "__main__":
    unittest.main()
