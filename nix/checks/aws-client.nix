{ pkgs }:

# S3 client for test setup and assertions against the local RustFS. Checksums
# stay opt-in because stock CLI uploads otherwise add trailers the test does not
# need to exercise.
{
  environment.etc."aws-config".text = ''
    [default]
    endpoint_url = http://localhost:9000
    region = us-east-1
    aws_access_key_id = rustfsadmin
    aws_secret_access_key = rustfsadmin
    request_checksum_calculation = when_required
    response_checksum_validation = when_required
    s3 =
      addressing_style = path
  '';
  environment.variables.AWS_CONFIG_FILE = "/etc/aws-config";
  environment.systemPackages = [ pkgs.awscli2 ];
}
