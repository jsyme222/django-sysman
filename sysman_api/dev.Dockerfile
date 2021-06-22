FROM python:3.9-buster
ENV PYTHONUNBUFFERED=1
RUN apt update && apt install git nmap -y
RUN git clone https://bitbucket.org/xael/python-nmap 
WORKDIR /python-nmap
RUN python setup.py install
WORKDIR /api
COPY requirements.txt /api/
RUN pip install -r requirements.txt
COPY . /api
