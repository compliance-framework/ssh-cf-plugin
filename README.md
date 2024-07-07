# Cloud Compliance Framework - Azure Plugin
# ssh-cf-plugin


## Development

First, change main.go to suit your needs.

Then run

```sh
go mod init [YOUR PROVIDER NAME]-cf-plugin     # eg cloudprovider-cf-plugin
```

If you push to GitHub with an appropriate `GITHUB_TOKEN` in your secrets,
then the image should be built and made publicly-available to Compliance Framework.
