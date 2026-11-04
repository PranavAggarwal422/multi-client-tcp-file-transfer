from key_manager import (
    load_public_key,
    load_signing_public_key,
    get_fingerprint
)


TRUSTED_FINGERPRINTS = {
    "Alice": {
        "encryption": "86cafc6630b5198d3d9fd95d366908a40e0aafe5975e85cd3928769a949f0797",
        "signing": "4d2a17eb7c7064e78adcbd10a7a910af89404939daac1c82fe772e695115b6b4"
    },
    "Bob": {
        "encryption": "2eb9633b7e05f492aed249e5c38f38b274090ad8911a0cd76a38fcd3bd5606ec",
        "signing": "ed86772f7dd55d586893d5962be78363fe79f7c6bea5b40359fd3ed1e5dee95b"
    },
    "Charlie": {
        "encryption": "2bdd03d94572255993dab88d5a5410e98edbd819427e94e9a42ffbba7e7bb785",
        "signing": "e63aa18289aff03ad126509ec10ecda1dde3334a7220260de7aaf85a0404fa9e"
    },
    "David": {
        "encryption": "95282b625744778b442c157891d816830e8c388d7e315b7307e22d046c9c86df",
        "signing": "e3f5b64d65351155fb61219e9add6c51aac310013dc25eb31796ebcf29776088"
    },
    "Eve": {
        "encryption": "8c03a117990337c790f448513c233734053b3cbbe9ee7eebad0db5a885c2722c",
        "signing": "5a3d7c8a2bf70e0d63645d27969fdf9b9dfcb743b6a6f19c5722ce13b9bcfe5e"
    },
    "Frank": {
        "encryption": "e18c5a97ed3c44bc049cf4b3daa27f07e284cd1323c22dea85f3f1a4a3cb2c65",
        "signing": "41846e470359b9330e15b52d89fa4b8c0b858ee2eda94871c89ba7e663450e75"
    },
    "Grace": {
        "encryption": "a1c8a0b5c550e4b5154215855b01763a63355d4842163fb1ea9f8bcbd91eb3c2",
        "signing": "d4ec174eb0e34bf9db261943f9f674e9597184f82f7066a71a9a52b6e97c9962"
    },
    "Heidi": {
        "encryption": "910e531db590157ea7d58bd5a025508417a3d6676b30f02d7a8b3fe1c5974172",
        "signing": "70dab5abe136e393f308f8adb87637b0f2445a41948102311173e185db846529"
    },
    "Judy": {
        "encryption": "e8050c4ae6380d2c24b1a556c2b22b785817d86ab138fab66e405648a2987bdc",
        "signing": "655bcea1e4d325909b32dfb886398126e16013dcb2ac8b27d50974f4c15f5a0b"
    },
    "Ivan": {
        "encryption": "7839fdf01a80408c85dead2e0d24e5c8cb4f49f3163f0398ed352fd587170321",
        "signing": "9cfb8726e809f9b036db4ce5cc33f3b2157570baad4e5ad4cb7caadc6ef15409"
    }
}


def verify_trusted_key(username, key_type):
    """Check a public key against its independently pinned fingerprint."""

    if username not in TRUSTED_FINGERPRINTS:
        raise ValueError(f"Unknown user: {username}")

    if key_type == "encryption":
        public_key = load_public_key(username)
    elif key_type == "signing":
        public_key = load_signing_public_key(username)
    else:
        raise ValueError("Key type must be 'encryption' or 'signing'")

    actual = get_fingerprint(public_key)
    expected = TRUSTED_FINGERPRINTS[username][key_type]

    if actual != expected:
        raise ValueError(
            f"UNTRUSTED {key_type} key for {username}! "
            "Fingerprint mismatch."
        )

    return True