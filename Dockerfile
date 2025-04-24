FROM python:3.12-alpine AS test_webhook

RUN apk update && apk upgrade && apk add git

WORKDIR /
RUN git clone https://github.com/SebastienGardoll/test_webhook.git

WORKDIR /test_webhook
RUN pip install .

CMD ["python","-c","from start import main; main()"]
