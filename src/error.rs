use http::StatusCode;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct S3Error {
    pub code: &'static str,
    pub status: StatusCode,
    pub message: Cow<'static, str>,
}

pub type S3Result<T> = Result<T, S3Error>;

impl S3Error {
    pub fn new(code: &'static str, status: StatusCode, message: impl Into<Cow<'static, str>>) -> Self {
        S3Error { code, status, message: message.into() }
    }

    pub fn internal(msg: impl std::fmt::Display) -> Self {
        Self::new("InternalError", StatusCode::INTERNAL_SERVER_ERROR, format!("We encountered an internal error: {msg}"))
    }
}

macro_rules! errors {
    ($($fn:ident => $code:literal, $status:ident, $msg:literal;)*) => {
        impl S3Error {
            $(pub fn $fn() -> Self { Self::new($code, StatusCode::$status, $msg) })*
        }
    };
}

errors! {
    access_denied => "AccessDenied", FORBIDDEN, "Access Denied.";
    signature_mismatch => "SignatureDoesNotMatch", FORBIDDEN, "The request signature we calculated does not match the signature you provided.";
    invalid_access_key => "InvalidAccessKeyId", FORBIDDEN, "The AWS Access Key Id you provided does not exist in our records.";
    request_time_skewed => "RequestTimeTooSkewed", FORBIDDEN, "The difference between the request time and the server's time is too large.";
    expired_presign => "AccessDenied", FORBIDDEN, "Request has expired.";
    no_such_bucket => "NoSuchBucket", NOT_FOUND, "The specified bucket does not exist.";
    no_such_key => "NoSuchKey", NOT_FOUND, "The specified key does not exist.";
    no_such_upload => "NoSuchUpload", NOT_FOUND, "The specified multipart upload does not exist.";
    bucket_exists => "BucketAlreadyOwnedByYou", CONFLICT, "Your previous request to create the named bucket succeeded and you already own it.";
    bucket_not_empty => "BucketNotEmpty", CONFLICT, "The bucket you tried to delete is not empty.";
    invalid_bucket_name => "InvalidBucketName", BAD_REQUEST, "The specified bucket is not valid.";
    key_too_long => "KeyTooLongError", BAD_REQUEST, "Your key is too long.";
    invalid_argument => "InvalidArgument", BAD_REQUEST, "Invalid argument.";
    invalid_request => "InvalidRequest", BAD_REQUEST, "Invalid request.";
    invalid_part => "InvalidPart", BAD_REQUEST, "One or more of the specified parts could not be found or the ETag did not match.";
    invalid_part_order => "InvalidPartOrder", BAD_REQUEST, "The list of parts was not in ascending order.";
    entity_too_small => "EntityTooSmall", BAD_REQUEST, "Your proposed upload is smaller than the minimum allowed object size.";
    malformed_xml => "MalformedXML", BAD_REQUEST, "The XML you provided was not well-formed or did not validate against our published schema.";
    bad_digest => "BadDigest", BAD_REQUEST, "The Content-MD5 or checksum you specified did not match what we received.";
    invalid_digest => "InvalidDigest", BAD_REQUEST, "The Content-MD5 you specified is not valid.";
    sha256_mismatch => "XAmzContentSHA256Mismatch", BAD_REQUEST, "The provided 'x-amz-content-sha256' header does not match what was computed.";
    incomplete_body => "IncompleteBody", BAD_REQUEST, "You did not provide the number of bytes specified by the Content-Length HTTP header.";
    invalid_range => "InvalidRange", RANGE_NOT_SATISFIABLE, "The requested range is not satisfiable.";
    precondition_failed => "PreconditionFailed", PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold.";
    not_modified => "NotModified", NOT_MODIFIED, "Not Modified.";
    method_not_allowed => "MethodNotAllowed", METHOD_NOT_ALLOWED, "The specified method is not allowed against this resource.";
    not_implemented => "NotImplemented", NOT_IMPLEMENTED, "A header or query you provided implies functionality that is not implemented.";
    entity_too_large => "EntityTooLarge", BAD_REQUEST, "Your proposed upload exceeds the maximum allowed size.";
    insufficient_storage => "InsufficientStorage", INSUFFICIENT_STORAGE, "The server does not have enough free disk space to store this object.";
    request_timeout => "RequestTimeout", BAD_REQUEST, "Your socket connection to the server was not read from or written to within the timeout period.";
}

impl From<std::io::Error> for S3Error {
    fn from(e: std::io::Error) -> Self {
        if e.raw_os_error() == Some(libc::ENOSPC) || e.raw_os_error() == Some(libc::EDQUOT) {
            return S3Error::insufficient_storage();
        }
        S3Error::internal(e)
    }
}

macro_rules! from_internal {
    ($($t:ty),*) => {$(
        impl From<$t> for S3Error {
            fn from(e: $t) -> Self { S3Error::internal(e) }
        }
    )*};
}

from_internal!(
    redb::Error,
    redb::StorageError,
    redb::TableError,
    redb::TransactionError,
    redb::CommitError,
    bincode::Error,
    tokio::task::JoinError
);

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for S3Error {}
