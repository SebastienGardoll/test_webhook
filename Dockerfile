FROM python:3.12-alpine AS esgvoc-backend

RUN apk update && apk upgrade && apk add git

WORKDIR /var/www
ADD https://github.com/SebastienGardoll/test_webhook.git test_webhook

WORKDIR /var/www/test_webhook
RUN pip install .

CMD ["python","-c","from start import main; main()"]
