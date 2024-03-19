"""
将各个模块进行封装和整合
各个模块继承Context_Child类来对接相应的Context类
Context_Child类通过createEvent创建事件
Context内部通过EventBus进行事件的传递，通过EventHook监听事件
而Event类为这些事件的封装

"""

CONTEXT_INIT = 0
PACKAGE_LOST = 0XFF00


class Event:
    """
    事件的封装
    
    EventId          (int) : 事件id，这是一个递增的事件id号，每次创建一个新事件，该值会增1，这个增，由上层的Context实例来维护
    ContentType (int) : 事件类型
    Payload     (any) : 事件内容
    
    其中CONTEXT_INIT(0)，PACKAGE_LOST(0xff00)为保留的事件类型
    其他的事件类型为自定义的事件类型
    
    """

    EventId = 0
    ContentType = 0
    Payload = None

    def __str__(self):

        return f"""

    [Event]
    ContentType : {hex(self.ContentType)}
    payload     : {self.Payload}

"""

    def debug_str(self, contentType_dict: dict, to_print=True):
        """
        用于debug时的输出
        
        contentType_dict  (dict) :用于将自定义的事件类型映射到对应的事件名
        to_print          (bool) : 是否通过print函数进行输出
        
        返回输出的字符串
        """

        string = f"""

    [Event]
    EventId      : {self.EventId}
    ContentType : {hex(contentType_dict[self.ContentType])}
    payload     : {self.Payload}

"""
        if to_print:
            print(string)

        return string

    def __init__(self, EventId: int, ContentType: int, payload=None):
        self.EventId = EventId
        self.ContentType = ContentType
        self.Payload = payload


class Context:
    """
    将各个模块进行封装和整合用的抽象类。
    由子类继承实现

    各个模块通过EventHook挂载到EventBus函数内部形成事件链
    事件的传递通过EventBus进行
    
    同时也支持异常或警告的传递，使用方法也和EventBus类似，也是通过
    EventBus进行挂载，形成异常链和警告链。
    """

    event_cur_id = 0

    def EventBus(self, event: Event):
        """
        各个模块通过EventHook挂载到EventBus函数内部
        事件的传递通过EventBus进行
        
        """
        pass

    def EventHook(self, function, status: tuple, event: Event):
        """用于监听指定的事件类型

        Args:
            function (function): 设置触发后的回调函数。触发后，会调用该函数并传入event参数
            status (tuple): 设置需要监听的事件类型。用元组包装一个或多个事件类型
            event (Event): 传入事件

        Returns:
            Event : 一般这个返回值没有什么作用
        """

        if event.ContentType in status:
            function(event)

        return event

    def EventException(self, event: Event):
        """用法和EventBus类似，用于构建异常链，默认为抛出异常

        Args:
            event (Event): 创建的事件类
        """
        self._ContextException(event)

    def EventWarning(self, event: Event):
        """用法和EventBus类似，用于构建警告链
        Args:
            event (Event): 创建的事件类
        """

        pass

    def _ContextException(self, event: Event):
        raise Exception("[Context Exception] : %s" % event)

    def Loop(self):
        """
        该Context的主循环函数，需由子类重写改方法
        一般插入各模块的主循环函数
        在Context_Child类中的主循环函数为check函数
        """
        pass


class Context_Child:
    """
    需要对接Context类的模块所继承的抽象类，提供对接Context的方法
    
    根据需要，子类可重写check方法与soft_reset方法
    """

    context_object = None

    def __init__(self, context: Context):
        """
        初始化Context_Child类，传入需对接的Context

        Args:
            context (Context): 需对接的Context实例
        """
        self.setContext(context)

    def check(self):
        """
        该函数一般在Context类的Loop中调用
        由子类进行重写
        用于检查各模块的当前状态并进行处理，使各模块正常工作
        """
        pass

    def soft_reset(self,event: Event):
        """
        该函数用于重置模块的工作状态
        由子类进行重写

        """
        pass

    def package_throw(self, event: Event):
        """
        将一个事件标记为丢弃，丢弃的事件不会再被捕获

        Args:
            event (Event): 需要丢弃的事件
        """
        event.ContentType = PACKAGE_LOST
        event.Payload = None

    def package_reset(self,
                      event: Event,
                      contentType: int = None,
                      payload=None):
        """修改一个事件的类型与内容

        Args:
            event (Event): 需要修改的事件
            contentType (int, optional): 修改成该事件类型。为空则不修改事件类型
            payload (any): 修改成该事件内容，默认修改成None
        """
        if contentType:
            event.ContentType = contentType
        event.Payload = payload

    def setContext(self, context: Context):
        """将需要对接的Context实例修改为该参数

        Args:
            context (Context): Context实例
        """
        self.context_object = context

    def createEvent(self, contentType: int, payload=None):
        """创建一个事件，创建完这个事件后会立刻调用context实例的EventBus函数并传入该事件

        Args:
            contentType (int): 事件类型
            payload (事件内容, optional): 事件内容默认为None
        
        Return:
            int: 事件ID
        """
        
        self.context_object.event_cur_id += 1
        self.context_object.EventBus(Event(self.context_object.event_cur_id,contentType, payload))
        return self.context_object.event_cur_id

    def raiseException(self, contentType: int, payload=None):
        """创建一个事件，并调用context实例的EventException函数并传入该事件

        Args:
            contentType (int): 事件类型
            payload (事件内容, optional): 事件内容默认为None.
            
        Return:
            int: 事件ID
        """
        self.context_object.event_cur_id += 1
        self.context_object.EventException(Event(self.context_object.event_cur_id,contentType, payload))
        return self.context_object.event_cur_id

    def raiseWarning(self, contentType: int, payload=None):
        """创建一个事件，并调用context实例的EventWarning函数并传入该事件

        Args:
            contentType (int): 事件类型
            payload (事件内容, optional): 事件内容默认为None.
        
        Return:
            int: 事件ID
        """
        self.context_object.event_cur_id += 1
        self.context_object.EventWarning(Event(self.context_object.event_cur_id,contentType, payload))
        return self.context_object.event_cur_id
