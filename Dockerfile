FROM apify/actor-python-playwright:3.14-1.57.0

USER myuser

COPY --chown=myuser:myuser requirements.txt ./

RUN echo "Python version:" \
 && python --version \
 && echo "Installing dependencies:" \
 && pip install -r requirements.txt

COPY --chown=myuser:myuser . ./

RUN python3 -m compileall -q src/

CMD ["python3", "-m", "src"]
