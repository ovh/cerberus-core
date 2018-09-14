
from redis import Redis

from rq import Queue, get_failed_queue
from rq_scheduler import Scheduler

MODULE_PATH = 'abuse.tasks'


class Queues(object):

    default = None
    email = None
    kpi = None
    scheduler = None
    failed_queue = None

    @classmethod
    def set_up(cls, config):

        for queue_name in ('default', 'email', 'kpi'):
            queue = Queue(
                connection=Redis(
                    host=config['host'],
                    port=int(config['port']),
                    password=config['password'],
                ),
                **config['queues'][queue_name]
            )
            setattr(cls, queue_name, queue)

        cls.scheduler = Scheduler(
            connection=Redis(
                host=config['host'],
                port=int(config['port']),
                password=config['password'],
            )
        )

        cls.failed_queue = get_failed_queue(
            connection=Redis(
                host=config['host'],
                port=int(config['port']),
                password=config['password'],
            ),
        )

    @classmethod
    def enqueue(cls, func_name, queue_name='default', *args, **kwargs):

        return getattr(cls, queue_name).enqueue(
            func_name,
            *args,
            **kwargs
        )

    @classmethod
    def cancel(cls, job_id):

        cls.scheduler.cancel(job_id)


def is_job_scheduled(job_id):

    return job_id in Queues.scheduler


def cancel(job_id):

    Queues.cancel(job_id)


def enqueue(func_name, queue='default', *args, **kwargs):

    return Queues.enqueue(
        '{}.{}'.format(MODULE_PATH, func_name),
        queue_name=queue,
        *args,
        **kwargs
    )


def enqueue_in(timedelta, func_name, **kwargs):

    return Queues.scheduler.enqueue_in(
        timedelta,
        '{}.{}'.format(MODULE_PATH, func_name),
        **kwargs
    )
