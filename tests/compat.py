"""S3 compatibility test using boto3 against a running server.

Usage:
    pip install boto3 awscrt
    ./target/release/s3 --data /tmp/s3-test &
    python3 tests/compat.py            # EP=http://host:port to override
"""
import hashlib, io, os, sys, urllib.request, urllib.error
import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

EP = os.environ.get("EP", "http://127.0.0.1:9000")
AK = os.environ.get("S3_ACCESS_KEY", "test")
SK = os.environ.get("S3_SECRET_KEY", "test-secret-123")
MD5_ETAGS = os.environ.get("FAST_ETAG") != "1"


def client(secret=SK, **cfg):
    return boto3.client("s3", endpoint_url=EP, aws_access_key_id=AK, aws_secret_access_key=secret, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}, **cfg))


s3 = client()
B = "compat-test"
ok = 0


def check(cond, msg):
    global ok
    if not cond:
        print("FAIL:", msg)
        sys.exit(1)
    ok += 1


def err_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def md5_etag(b):
    return '"%s"' % hashlib.md5(b).hexdigest()


# cleanup from previous runs
try:
    for pg in s3.get_paginator("list_objects_v2").paginate(Bucket=B):
        for o in pg.get("Contents", []):
            s3.delete_object(Bucket=B, Key=o["Key"])
    for u in s3.list_multipart_uploads(Bucket=B).get("Uploads", []):
        s3.abort_multipart_upload(Bucket=B, Key=u["Key"], UploadId=u["UploadId"])
    s3.delete_bucket(Bucket=B)
except ClientError:
    pass

# buckets
s3.create_bucket(Bucket=B)
# Re-creating your own bucket: 200 in us-east-1 (AWS legacy behaviour), 409 elsewhere.
check(err_code(lambda: s3.create_bucket(Bucket=B)) in (None, "BucketAlreadyOwnedByYou"), "dup bucket")
check(err_code(lambda: s3.create_bucket(Bucket="Bad_Name")) == "InvalidBucketName", "bad bucket name")
check(B in [b["Name"] for b in s3.list_buckets()["Buckets"]], "list buckets")
s3.head_bucket(Bucket=B)
check(err_code(lambda: s3.head_bucket(Bucket="nope-nope")) in ("404", "NoSuchBucket"), "head missing bucket")
check(s3.get_bucket_location(Bucket=B).get("LocationConstraint") in (None, ""), "location")
check(err_code(lambda: client(secret="wrong").list_buckets()) == "SignatureDoesNotMatch", "bad secret")

# small (inline) object with metadata
body = b"hello world"
r = s3.put_object(Bucket=B, Key="small.txt", Body=body, ContentType="text/plain", Metadata={"foo": "bar"}, CacheControl="max-age=60")
check(not MD5_ETAGS or r["ETag"] == md5_etag(body), "small etag")
g = s3.get_object(Bucket=B, Key="small.txt")
check(g["Body"].read() == body, "small body")
check(g["ContentType"] == "text/plain" and g["Metadata"] == {"foo": "bar"} and g["CacheControl"] == "max-age=60", "small meta")
check(s3.head_object(Bucket=B, Key="small.txt")["ContentLength"] == len(body), "head length")
check(s3.get_object(Bucket=B, Key="small.txt", Range="bytes=6-")["Body"].read() == b"world", "inline range")
check(err_code(lambda: s3.get_object(Bucket=B, Key="small.txt", IfNoneMatch=r["ETag"])) == "304", "304")
check(err_code(lambda: s3.get_object(Bucket=B, Key="small.txt", IfMatch='"nope"')) == "PreconditionFailed", "412")
check(err_code(lambda: s3.get_object(Bucket=B, Key="missing")) == "NoSuchKey", "nosuchkey")
check(err_code(lambda: s3.get_object(Bucket="nope-nope", Key="x")) == "NoSuchBucket", "nosuchbucket")
check(err_code(lambda: s3.put_object(Bucket=B, Key="small.txt", Body=b"x", IfNoneMatch="*")) == "PreconditionFailed", "if-none-match put")
s3.put_object(Bucket=B, Key="empty", Body=b"")
check(s3.get_object(Bucket=B, Key="empty")["Body"].read() == b"", "empty object")

# file-backed object
big = os.urandom(3 * 1024 * 1024 + 123)
r = s3.put_object(Bucket=B, Key="dir/big.bin", Body=big)
check(not MD5_ETAGS or r["ETag"] == md5_etag(big), "big etag")
check(s3.get_object(Bucket=B, Key="dir/big.bin")["Body"].read() == big, "big body")
check(s3.get_object(Bucket=B, Key="dir/big.bin", Range="bytes=1000-2000999")["Body"].read() == big[1000:2001000], "big range")
check(s3.get_object(Bucket=B, Key="dir/big.bin", Range="bytes=-10")["Body"].read() == big[-10:], "suffix range")
check(err_code(lambda: s3.get_object(Bucket=B, Key="dir/big.bin", Range="bytes=99999999-")) == "InvalidRange", "416")
s3.put_object(Bucket=B, Key="dir/big.bin", Body=b"replaced")
check(s3.get_object(Bucket=B, Key="dir/big.bin")["Body"].read() == b"replaced", "overwrite file with inline")

# special keys
weird = ["a b/c+d&e=f?g#h", "ünï/日本語.txt", "x%20y", "tilde~/(parens)!'*", "a//double"]
for k in weird:
    s3.put_object(Bucket=B, Key=k, Body=k.encode())
    check(s3.get_object(Bucket=B, Key=k)["Body"].read() == k.encode(), "weird key %r" % k)

# listing
for i in range(5):
    s3.put_object(Bucket=B, Key="list/sub%d/f.txt" % i, Body=b"x")
    s3.put_object(Bucket=B, Key="list/f%d.txt" % i, Body=b"x")
r = s3.list_objects_v2(Bucket=B, Prefix="list/", Delimiter="/")
check([p["Prefix"] for p in r["CommonPrefixes"]] == ["list/sub%d/" % i for i in range(5)], "common prefixes")
check([o["Key"] for o in r["Contents"]] == ["list/f%d.txt" % i for i in range(5)], "list contents")
pages = list(s3.get_paginator("list_objects_v2").paginate(Bucket=B, Prefix="list/", Delimiter="/", PaginationConfig={"PageSize": 3}))
got = [p["Prefix"] for pg in pages for p in pg.get("CommonPrefixes", [])] + [o["Key"] for pg in pages for o in pg.get("Contents", [])]
check(len(pages) == 4 and sorted(got) == sorted(["list/sub%d/" % i for i in range(5)] + ["list/f%d.txt" % i for i in range(5)]), "v2 pagination")
pages = list(s3.get_paginator("list_objects").paginate(Bucket=B, Prefix="list/", PaginationConfig={"PageSize": 4}))
check(sum(len(p.get("Contents", [])) for p in pages) == 10, "v1 pagination")
allkeys = [o["Key"] for o in s3.list_objects_v2(Bucket=B)["Contents"]]
check(allkeys == sorted(allkeys, key=lambda s: s.encode()) and all(k in allkeys for k in weird), "full listing order")
check(s3.list_objects_v2(Bucket=B, StartAfter="list/sub3/f.txt", Prefix="list/")["KeyCount"] == 1, "start-after")

# copy
s3.copy_object(Bucket=B, Key="copy.txt", CopySource={"Bucket": B, "Key": "small.txt"})
c = s3.get_object(Bucket=B, Key="copy.txt")
check(c["Body"].read() == body and c["Metadata"] == {"foo": "bar"}, "copy inline")
s3.put_object(Bucket=B, Key="tocopy.bin", Body=big)
s3.copy_object(Bucket=B, Key="copied.bin", CopySource={"Bucket": B, "Key": "tocopy.bin"}, MetadataDirective="REPLACE", Metadata={"new": "1"}, ContentType="x/y")
s3.delete_object(Bucket=B, Key="tocopy.bin")
c = s3.get_object(Bucket=B, Key="copied.bin")
check(c["Body"].read() == big and c["Metadata"] == {"new": "1"} and c["ContentType"] == "x/y", "copy file + replace, survives source delete")
check(err_code(lambda: s3.copy_object(Bucket=B, Key="small.txt", CopySource={"Bucket": B, "Key": "small.txt"})) == "InvalidRequest", "self copy")

# multipart
p1, p2 = os.urandom(5 << 20), os.urandom(5 << 20)
uid = s3.create_multipart_upload(Bucket=B, Key="mp.bin", ContentType="app/mp", Metadata={"m": "1"})["UploadId"]
e1 = s3.upload_part(Bucket=B, Key="mp.bin", UploadId=uid, PartNumber=1, Body=p1)["ETag"]
s3.upload_part(Bucket=B, Key="mp.bin", UploadId=uid, PartNumber=2, Body=b"will be replaced")
e2 = s3.upload_part(Bucket=B, Key="mp.bin", UploadId=uid, PartNumber=2, Body=p2)["ETag"]
e3 = s3.upload_part_copy(Bucket=B, Key="mp.bin", UploadId=uid, PartNumber=3, CopySource={"Bucket": B, "Key": "copied.bin"}, CopySourceRange="bytes=0-1233")["CopyPartResult"]["ETag"]
p3 = big[:1234]
check([p["PartNumber"] for p in s3.list_parts(Bucket=B, Key="mp.bin", UploadId=uid)["Parts"]] == [1, 2, 3], "list parts")
check(uid in [u["UploadId"] for u in s3.list_multipart_uploads(Bucket=B)["Uploads"]], "list uploads")
check(err_code(lambda: s3.complete_multipart_upload(Bucket=B, Key="mp.bin", UploadId=uid, MultipartUpload={"Parts": [{"PartNumber": 2, "ETag": e2}, {"PartNumber": 1, "ETag": e1}]})) == "InvalidPartOrder", "part order")
check(err_code(lambda: s3.complete_multipart_upload(Bucket=B, Key="mp.bin", UploadId=uid, MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"bad"'}]})) == "InvalidPart", "bad part")
r = s3.complete_multipart_upload(Bucket=B, Key="mp.bin", UploadId=uid, MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}, {"PartNumber": 3, "ETag": e3}]})
if MD5_ETAGS:
    exp = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in (p1, p2, p3))).hexdigest() + "-3"
    check(r["ETag"] == '"%s"' % exp, "multipart etag")
full = p1 + p2 + p3
g = s3.get_object(Bucket=B, Key="mp.bin")
check(g["Body"].read() == full and g["ContentType"] == "app/mp" and g["Metadata"] == {"m": "1"}, "multipart body")
check(s3.get_object(Bucket=B, Key="mp.bin", Range="bytes=%d-%d" % ((5 << 20) - 10, (5 << 20) + 9))["Body"].read() == full[(5 << 20) - 10:(5 << 20) + 10], "cross-part range")
pn = s3.get_object(Bucket=B, Key="mp.bin", PartNumber=2)
check(pn["Body"].read() == p2 and pn["PartsCount"] == 3, "get by part number")
check(err_code(lambda: s3.list_parts(Bucket=B, Key="mp.bin", UploadId=uid)) == "NoSuchUpload", "upload gone after complete")
del p1, p2, full

up = s3.create_multipart_upload(Bucket=B, Key="aborted")
s3.upload_part(Bucket=B, Key="aborted", UploadId=up["UploadId"], PartNumber=1, Body=b"abc")
s3.abort_multipart_upload(Bucket=B, Key="aborted", UploadId=up["UploadId"])
check(err_code(lambda: s3.upload_part(Bucket=B, Key="aborted", UploadId=up["UploadId"], PartNumber=1, Body=b"abc")) == "NoSuchUpload", "abort")

# transfer manager: threaded multipart upload + ranged parallel download
data = os.urandom(12 << 20)
tc = TransferConfig(multipart_threshold=5 << 20, multipart_chunksize=5 << 20, max_concurrency=4)
s3.upload_fileobj(io.BytesIO(data), B, "tm.bin", Config=tc)
out = io.BytesIO()
s3.download_fileobj(B, "tm.bin", out, Config=tc)
check(out.getvalue() == data, "transfer manager roundtrip")
del data, out

# flexible checksums (aws-chunked with trailers / headers)
for algo in ("CRC32", "CRC32C", "SHA256"):
    s3.put_object(Bucket=B, Key="ck-" + algo, Body=b"checksum me" * 1000, ChecksumAlgorithm=algo)
    check(s3.get_object(Bucket=B, Key="ck-" + algo)["Body"].read() == b"checksum me" * 1000, "checksum " + algo)

# presigned URLs (boto3 default = SigV2, plus SigV4)
url = s3.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "small.txt"}, ExpiresIn=60)
check(urllib.request.urlopen(url).read() == body, "presigned v2 get")
url = s3.generate_presigned_url("put_object", Params={"Bucket": B, "Key": "presigned-put", "ContentType": "text/plain"}, ExpiresIn=60)
urllib.request.urlopen(urllib.request.Request(url, data=b"via presign", method="PUT", headers={"Content-Type": "text/plain"}))
check(s3.get_object(Bucket=B, Key="presigned-put")["Body"].read() == b"via presign", "presigned v2 put")
url = client(signature_version="s3v4").generate_presigned_url(
    "get_object", Params={"Bucket": B, "Key": "small.txt", "ResponseContentDisposition": "attachment; filename=x.txt"}, ExpiresIn=60)
resp = urllib.request.urlopen(url)
check(resp.read() == body and resp.headers["Content-Disposition"] == "attachment; filename=x.txt", "presigned v4 + response override")
try:
    urllib.request.urlopen(url.replace("X-Amz-Signature=", "X-Amz-Signature=0"))
    check(False, "tampered presign accepted")
except urllib.error.HTTPError as e:
    check(e.code == 403, "tampered presign 403")

# multi-delete + bucket removal
check(err_code(lambda: s3.delete_bucket(Bucket=B)) == "BucketNotEmpty", "bucket not empty")
keys = [o["Key"] for pg in s3.get_paginator("list_objects_v2").paginate(Bucket=B) for o in pg.get("Contents", [])]
r = s3.delete_objects(Bucket=B, Delete={"Objects": [{"Key": k} for k in keys]})
check(len(r["Deleted"]) == len(keys), "multi delete")
check(s3.list_objects_v2(Bucket=B)["KeyCount"] == 0, "empty after delete")
s3.delete_bucket(Bucket=B)
check(B not in [b["Name"] for b in s3.list_buckets()["Buckets"]], "bucket deleted")
print("ALL OK:", ok, "checks")
