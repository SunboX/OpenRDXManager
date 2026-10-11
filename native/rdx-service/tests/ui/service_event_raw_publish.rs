use rdx_service::model::OperationEvent;
use rdx_service::service::ServiceEventSink;

fn publish_caller_authored_terminal(sink: &ServiceEventSink, event: OperationEvent) {
    let _ = sink.publish(event);
}

fn main() {}
