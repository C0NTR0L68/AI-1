import ctypes
import os
from ctypes import wintypes

import pytest

import app.memory_crypto as memory_crypto
from app.memory_crypto import (
    CRYPTPROTECT_UI_FORBIDDEN,
    MemoryCryptoError,
    protect_for_current_user,
    unprotect_for_current_user,
)


@pytest.mark.skipif(os.name != "nt", reason="Uses Windows CurrentUser DPAPI")
def test_current_user_dpapi_round_trip_with_synthetic_data():
    plaintext = b"synthetic-memory-payload"

    ciphertext = protect_for_current_user(plaintext)

    assert type(ciphertext) is bytes
    assert ciphertext != plaintext
    assert unprotect_for_current_user(ciphertext) == plaintext


@pytest.mark.skipif(os.name != "nt", reason="Uses Windows CurrentUser DPAPI")
def test_corrupt_dpapi_ciphertext_is_rejected():
    ciphertext = bytearray(protect_for_current_user(b"synthetic-corruption-check"))
    ciphertext[-1] ^= 0x01

    with pytest.raises(MemoryCryptoError) as error:
        unprotect_for_current_user(ciphertext)

    assert error.value.operation == "unprotect"
    assert b"synthetic-corruption-check" not in str(error.value).encode()


def test_protect_api_failure_is_redacted_and_disables_ui(monkeypatch):
    observed_flags = []

    class FakeCrypt32:
        def CryptProtectData(self, input_blob, description, entropy, reserved, prompt, flags, output):
            observed_flags.append(flags)
            return 0

    class FakeKernel32:
        @staticmethod
        def LocalFree(pointer):
            return None

    monkeypatch.setattr(memory_crypto, "_load_apis", lambda: (FakeCrypt32(), FakeKernel32()))
    monkeypatch.setattr(memory_crypto, "_last_error", lambda: 87)
    secret = b"SYNTHETIC_SECRET_MUST_NOT_APPEAR"

    with pytest.raises(MemoryCryptoError) as error:
        protect_for_current_user(secret)

    assert error.value.operation == "protect"
    assert error.value.winerror == 87
    assert secret.decode() not in str(error.value)
    assert observed_flags == [CRYPTPROTECT_UI_FORBIDDEN]


def test_unprotect_failure_frees_outputs_and_never_returns_input(monkeypatch):
    allocations = []
    freed = []
    observed_flags = []

    class FakeCrypt32:
        def CryptUnprotectData(
            self, input_blob, description, entropy, reserved, prompt, flags, output
        ):
            observed_flags.append(flags)
            description_out = ctypes.cast(
                description, ctypes.POINTER(wintypes.LPWSTR)
            )
            description_buffer = ctypes.create_unicode_buffer("synthetic-description")
            description_out[0] = ctypes.cast(description_buffer, wintypes.LPWSTR)
            plaintext_buffer = (ctypes.c_ubyte * 4)(1, 2, 3, 4)
            output_blob = ctypes.cast(
                output, ctypes.POINTER(memory_crypto._DataBlob)
            ).contents
            output_blob.cbData = len(plaintext_buffer)
            output_blob.pbData = ctypes.cast(
                plaintext_buffer, ctypes.POINTER(ctypes.c_ubyte)
            )
            allocations.extend((description_buffer, plaintext_buffer))
            return 0

    class FakeKernel32:
        @staticmethod
        def LocalFree(pointer):
            freed.append(pointer)
            return None

    monkeypatch.setattr(memory_crypto, "_load_apis", lambda: (FakeCrypt32(), FakeKernel32()))
    monkeypatch.setattr(memory_crypto, "_last_error", lambda: 13)
    ciphertext = b"SYNTHETIC_INVALID_CIPHERTEXT"

    with pytest.raises(MemoryCryptoError) as error:
        unprotect_for_current_user(ciphertext)

    assert error.value.operation == "unprotect"
    assert error.value.winerror == 13
    assert ciphertext.decode() not in str(error.value)
    assert observed_flags == [CRYPTPROTECT_UI_FORBIDDEN]
    assert len(freed) == 2


def test_output_size_and_pointer_are_validated_without_unsafe_memset(monkeypatch):
    buffer = (ctypes.c_ubyte * 4)(1, 2, 3, 4)
    blob = memory_crypto._DataBlob(
        0xFFFFFFFF,
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    released = []

    class FakeKernel32:
        @staticmethod
        def LocalFree(pointer):
            released.append(pointer)
            return None

    def forbidden_memset(*args):
        raise AssertionError("DPAPI output size must not control a memory write")

    monkeypatch.setattr(memory_crypto.ctypes, "memset", forbidden_memset)
    with pytest.raises(MemoryCryptoError, match="invalid_output"):
        memory_crypto._copy_output(blob, 64)

    expected_pointer = ctypes.cast(buffer, ctypes.c_void_p).value
    memory_crypto._release_blob(FakeKernel32(), blob)
    assert released == [expected_pointer]
    assert blob.cbData == 0
    assert not blob.pbData

    missing_pointer = memory_crypto._DataBlob(
        1, ctypes.POINTER(ctypes.c_ubyte)()
    )
    with pytest.raises(MemoryCryptoError, match="invalid_output"):
        memory_crypto._copy_output(missing_pointer, 64)
    memory_crypto._release_blob(FakeKernel32(), missing_pointer)


def test_bytes_input_uses_borrowed_buffer_without_plaintext_copy():
    plaintext = b"synthetic\x00payload"

    blob, keepalive = memory_crypto._input_blob(plaintext, 64)

    assert blob.cbData == len(plaintext)
    assert ctypes.string_at(blob.pbData, blob.cbData) == plaintext
    assert keepalive[0] is plaintext


def test_dpapi_failure_remains_primary_when_output_cleanup_fails(monkeypatch):
    output_storage = (ctypes.c_ubyte * 4)(1, 2, 3, 4)

    class FakeCrypt32:
        def CryptProtectData(self, input_blob, description, entropy, reserved, prompt, flags, output):
            blob = ctypes.cast(
                output, ctypes.POINTER(memory_crypto._DataBlob)
            ).contents
            blob.cbData = 4
            blob.pbData = ctypes.cast(
                output_storage, ctypes.POINTER(ctypes.c_ubyte)
            )
            return 0

    class FakeKernel32:
        @staticmethod
        def LocalFree(pointer):
            return pointer

    monkeypatch.setattr(memory_crypto, "_load_apis", lambda: (FakeCrypt32(), FakeKernel32()))
    monkeypatch.setattr(memory_crypto, "_last_error", lambda: 87)

    with pytest.raises(MemoryCryptoError) as error:
        protect_for_current_user(b"SYNTHETIC_SECRET")

    assert error.value.operation == "protect"
    assert error.value.winerror == 87
    assert "SYNTHETIC_SECRET" not in str(error.value)


def test_output_validation_error_remains_primary_when_cleanup_fails(monkeypatch):
    output_storage = (ctypes.c_ubyte * 1)(1)

    class FakeCrypt32:
        def CryptProtectData(self, input_blob, description, entropy, reserved, prompt, flags, output):
            blob = ctypes.cast(
                output, ctypes.POINTER(memory_crypto._DataBlob)
            ).contents
            blob.cbData = memory_crypto._MAX_CIPHERTEXT_BYTES + 1
            blob.pbData = ctypes.cast(
                output_storage, ctypes.POINTER(ctypes.c_ubyte)
            )
            return 1

    class FakeKernel32:
        @staticmethod
        def LocalFree(pointer):
            return pointer

    monkeypatch.setattr(memory_crypto, "_load_apis", lambda: (FakeCrypt32(), FakeKernel32()))

    with pytest.raises(MemoryCryptoError) as error:
        protect_for_current_user(b"synthetic")

    assert error.value.operation == "invalid_output"


@pytest.mark.parametrize(("succeeded", "size", "failure"), [
    (1, 4, None),
    (0, 4, "unprotect"),
    (1, 0xFFFFFFFF, "invalid_output"),
    (1, 0, None),
])
def test_native_plaintext_wipe_only_for_valid_success(monkeypatch, succeeded, size, failure):
    storage = (ctypes.c_ubyte * 6)(1, 2, 3, 4, 5, 6)
    address = ctypes.addressof(storage)
    freed = []

    class Crypt:
        def CryptUnprotectData(self, *args):
            blob = ctypes.cast(args[-1], ctypes.POINTER(memory_crypto._DataBlob)).contents
            blob.cbData = size
            blob.pbData = ctypes.cast(storage, ctypes.POINTER(ctypes.c_ubyte))
            return succeeded

    class Kernel:
        def LocalFree(self, pointer):
            freed.append((pointer, bytes(storage)))
            return None

    monkeypatch.setattr(memory_crypto, "_load_apis", lambda: (Crypt(), Kernel()))
    if failure:
        with pytest.raises(MemoryCryptoError, match=failure):
            unprotect_for_current_user(b"fake")
    else:
        assert unprotect_for_current_user(b"fake") == bytes(range(1, size + 1))
    expected = b"\0\0\0\0\x05\x06" if size == 4 and succeeded else bytes(range(1, 7))
    assert freed == [(address, expected)]


@pytest.mark.parametrize("copy_fails", [False, True])
def test_wipe_failure_still_frees_and_preserves_primary(monkeypatch, copy_fails):
    storage = (ctypes.c_ubyte * 3)(1, 2, 3)
    events = []

    class Crypt:
        def CryptUnprotectData(self, *args):
            blob = ctypes.cast(args[-1], ctypes.POINTER(memory_crypto._DataBlob)).contents
            blob.cbData = len(storage)
            blob.pbData = ctypes.cast(storage, ctypes.POINTER(ctypes.c_ubyte))
            return 1

    class Kernel:
        def LocalFree(self, pointer):
            events.append("free")
            return pointer

    def failed_wipe(*args):
        events.append("wipe")
        raise OSError("synthetic wipe failure")

    def failed_copy(*args):
        raise OSError("synthetic copy failure")

    monkeypatch.setattr(memory_crypto, "_load_apis", lambda: (Crypt(), Kernel()))
    monkeypatch.setattr(memory_crypto.ctypes, "memset", failed_wipe)
    if copy_fails:
        monkeypatch.setattr(memory_crypto.ctypes, "string_at", failed_copy)
    # An exception handled by the caller is not a primary error of this operation.
    try:
        raise ValueError("unrelated caller exception")
    except ValueError:
        with pytest.raises(MemoryCryptoError) as error:
            unprotect_for_current_user(b"fake")
    assert error.value.operation == ("invalid_output" if copy_fails else "wipe")
    assert events == ["wipe", "free"]
