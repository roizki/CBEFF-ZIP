import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
import yaml

class BiometricChecker:
    def __init__(self, database_path="biometric_db.yaml"):
        self.database_path = database_path
        self.load_database()

    def load_database(self):
        try:
            with open(self.database_path, "r") as f:
                self.db = yaml.safe_load(f) or []
        except FileNotFoundError:
            self.db = []

    def save_database(self):
        with open(self.database_path, "w") as f:
            yaml.dump(self.db, f)

    def check_and_store(self, name, dob, face_hash, finger_hash):
        bio_match = "NOT_DETECTED"
        face_dup = "NOT_DETECTED"
        finger_dup = "NOT_DETECTED"
        match_status = "STORED"

        for entry in self.db:
            if entry["name"] == name and entry["dob"] == dob:
                bio_match = "FULL_MATCH"
            elif entry["name"] == name or entry["dob"] == dob:
                bio_match = "PARTIAL_MATCH"

            if entry["face_hash"] == face_hash:
                face_dup = "DETECTED"

            if entry["finger_hash"] == finger_hash:
                finger_dup = "DETECTED"

        if bio_match == "FULL_MATCH" and face_dup == "DETECTED" and finger_dup == "DETECTED":
            match_status = "MATCH"
        elif face_dup == "DETECTED" or finger_dup == "DETECTED":
            match_status = "DUPLICATE_BIOMETRIC"

        if match_status == "STORED":
            self.db.append({
                "name": name,
                "dob": dob,
                "face_hash": face_hash,
                "finger_hash": finger_hash
            })
            self.save_database()

        return self.build_xml_result(name, dob, face_dup, finger_dup, bio_match, match_status)

    def build_xml_result(self, name, dob, face_status, finger_status, bio_status, match_status):
        root = ET.Element("BiometricTransactionResult")

        ET.SubElement(root, "TransactionTimestamp").text = datetime.utcnow().isoformat() + "Z"
        ET.SubElement(root, "BiographicData").text = f"{name}, DOB: {dob}"
        ET.SubElement(root, "FaceDuplicationStatus").text = face_status
        ET.SubElement(root, "FingerDuplicationStatus").text = finger_status
        ET.SubElement(root, "BiographicDuplicationStatus").text = bio_status
        ET.SubElement(root, "MatchStatus").text = match_status

    # Use minidom for pretty XML, but skip the XML declaration
        rough = ET.tostring(root, encoding="utf-8")
        parsed = minidom.parseString(rough)
        pretty = parsed.toprettyxml(indent="  ").split('\n', 1)[1]  # Skip the first line

        with open("biometric_result.xml", "w") as f:
            f.write(pretty)

        return pretty

    
checker = BiometricChecker()

xml_result = checker.check_and_store(
    name="Jane Doe",
    dob="1991-02-02",
    face_hash="face123456",
    finger_hash="finger654321"
)

print(xml_result)