from dycrption import decrypt_tgt_ticket


def Service_verify(request, key):
    request = request.encode("utf-8")
    data = decrypt_tgt_ticket(key, request)
    return data