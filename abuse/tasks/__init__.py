
import logging

from redis import Redis

from rq import Queue, get_failed_queue, push_connection
from rq.job import Job
from rq.exceptions import NoSuchJobError
from rq_scheduler import Scheduler
from ..logs import TaskLoggerAdapter
from ..utils.cache import RedisHandler

MODULE_PATH = "abuse.tasks"
ASYNC_TICKET_KEY = "rq_scheduler:ticket"

logger = TaskLoggerAdapter(logging.getLogger("rq.worker"), dict())


class Queues(object):

    default = None
    email = None
    kpi = None
    scheduler = None
    failed_queue = None

    @classmethod
    def set_up(cls, config):

        for queue_name in ("default", "email", "kpi"):
            queue = Queue(
                connection=Redis(
                    host=config["host"],
                    port=int(config["port"]),
                    password=config["password"],
                ),
                **config["queues"][queue_name]
            )
            setattr(cls, queue_name, queue)

        cls.scheduler = Scheduler(
            connection=Redis(
                host=config["host"],
                port=int(config["port"]),
                password=config["password"],
            )
        )

        cls.failed_queue = get_failed_queue(
            connection=Redis(
                host=config["host"],
                port=int(config["port"]),
                password=config["password"],
            )
        )

        push_connection(
            Redis(
                host=config["host"],
                port=int(config["port"]),
                password=config["password"],
            )
        )

    @classmethod
    def enqueue(cls, func_name, queue_name="default", *args, **kwargs):

        return getattr(cls, queue_name).enqueue(func_name, *args, **kwargs)

    @classmethod
    def cancel(cls, job_id):

        cls.scheduler.cancel(job_id)


def is_job_scheduled(job_id):

    return job_id in Queues.scheduler


def cancel_ticket_tasks(ticket_id):

    key = "{}:{}".format(ASYNC_TICKET_KEY, ticket_id)

    for job_id in RedisHandler.ldump(key):
        try:
            job = Job.fetch(job_id)
            logger.info(
                'Cancelling Job "{}", kwargs {} ({})'.format(
                    job.func_name, job.kwargs, job_id
                )
            )
        except NoSuchJobError:
            pass
        cancel(job_id)

    RedisHandler.client.delete(key)


def cancel(job_id):

    Queues.cancel(job_id)
    logger.info("Cancelled Job {}".format(job_id))


def enqueue(func_name, queue="default", *args, **kwargs):

    return Queues.enqueue(
        "{}.{}".format(MODULE_PATH, func_name), queue_name=queue, *args, **kwargs
    )


def enqueue_in(timedelta, func_name, **kwargs):

    async_job = Queues.scheduler.enqueue_in(
        timedelta, "{}.{}".format(MODULE_PATH, func_name), **kwargs
    )

    # async jobs tasks have to be cancelled when tickets are closed
    if kwargs.get("ticket_id"):
        RedisHandler.rpush(
            "{}:{}".format(ASYNC_TICKET_KEY, kwargs["ticket_id"]), async_job.id
        )

    return async_job
