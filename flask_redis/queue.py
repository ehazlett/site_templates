#!/usr/bin/env
import application
import pickle
import uuid
import settings

class DelayedResult(object):
    def __init__(self, key):
        self.redis = application.get_redis_connection()
        self.key = key
        self._rv = None
    @property
    def return_value(self):
        if self._rv is None:
            rv = self.redis.get(self.key)
            if rv is not None:
                self._rv = pickle.loads(rv)
        return self._rv

def task(f):
    def delay(*args, **kwargs):
        redis = application.get_redis_connection()
        qkey = settings.REDIS_QUEUE_KEY
        task_id = str(uuid.uuid4())
        key = '{0}:{1}'.format(qkey, task_id)
        s = pickle.dumps((f, key, args, kwargs))
        redis.rpush(settings.REDIS_QUEUE_KEY, s)
        return DelayedResult(key)
    f.delay = delay
    return f

def queue_daemon(app, rv_ttl=settings.REDIS_QUEUE_KEY_TTL):
    redis = application.get_redis_connection()
    while True:
        msg = redis.blpop(settings.REDIS_QUEUE_KEY)
        print('Running task: {0}'.format(msg))
        func, key, args, kwargs = pickle.loads(msg[1])
        try:
            rv = func(*args, **kwargs)
        except Exception, e:
            rv = e
        if rv is not None:
            redis.set(key, pickle.dumps(rv))
            redis.expire(key, rv_ttl)

if __name__=='__main__':
    from application import app
    print('Starting queue...')
    try:
        queue_daemon(app)
    except KeyboardInterrupt:
        print('Exiting...')

