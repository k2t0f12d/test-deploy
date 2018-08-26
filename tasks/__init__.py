from invoke import Collection, task
from tasks import tests, deploy


@task(default=True, pre=[tests.test])
def default(_):
    u""" Default Invoke will run tests """
    pass


@task(pre=deploy.cfn_up)
def cfn_up(_):
    u""" Stand up Cloudformation Resources """
    pass


@task(pre=deploy.cfn_down)
def cfn_down(_):
    u""" Teardown Cloudformation Resources """
    pass

@task(pre=deploy.cfn_update)
def cfn_update(_):
    u""" Update Cloudformation Stack """
    pass

ns = Collection()
ns.add_collection(Collection.from_module(tests))
ns.add_collection(Collection.from_module(deploy))

ns.add_task(default)
ns.add_task(tests.test)
ns.add_task(deploy.cfn_up)
ns.add_task(deploy.cfn_down)
ns.add_task(deploy.cfn_update)
