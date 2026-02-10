# opencertserver.lambda2

This project provides an alternative AWS Lambda entry point for OpenCertServer, supporting serverless deployment scenarios. It is designed to work with Amazon API Gateway and Application Load Balancer, enabling flexible cloud hosting for certificate authority services.

## Functionality
- AWS Lambda entry point for OpenCertServer (alternative configuration)
- Integrates with Amazon.Lambda.AspNetCoreServer for API Gateway and ALB
- Configures ASP.NET Core pipeline for Lambda

## Dependencies
- Microsoft.AspNetCore.Hosting
- Microsoft.Extensions.Hosting
- Amazon.Lambda.AspNetCoreServer
- OpenCertServer.Acme.Server, OpenCertServer.Ca, and related dependencies

Use this project for advanced Lambda deployment scenarios.
