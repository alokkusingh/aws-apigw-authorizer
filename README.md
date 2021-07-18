# aws-apigw-authorizer

### Sample JWT Token
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbG9ra3VzaW5naCIsIm5hbWUiOiJBbG9rIFNpbmdoIiwiaWF0IjoxNTE2MjM5MDIyfQ.ULte7pfCKz4DsqMsA2P_EyF9BaHJBozBwjYhlhwFKoU

### Sample Token Authrorizer Context
TokenAuthorizerContext{
type='TOKEN',
authorizationToken='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbG9ra3VzaW5naCIsIm5hbWUiOiJBbG9rIFNpbmdoIiwiaWF0IjoxNTE2MjM5MDIyfQ.ULte7pfCKz4DsqMsA2P_EyF9BaHJBozBwjYhlhwFKoU',
methodArn='arn:aws:execute-api:ap-south-1:040180071884:uxccnvz0w7/prod/POST/my-lambda/test'
}

### Authorizer Configuration

![alt text](https://github.com/alokkusingh/aws-apigw-authorizer/blob/main/media/TokenAuthorizer.png?raw=true "Authorizer Configuration")

### Resource API Configuration

![alt text](https://github.com/alokkusingh/aws-apigw-authorizer/blob/main/media/ResourceConfiguration.png?raw=true "Resource API Configuration")
