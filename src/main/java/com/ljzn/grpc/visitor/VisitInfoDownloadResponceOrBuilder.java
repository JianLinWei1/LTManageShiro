// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: visitor/visitor.service.proto

package com.ljzn.grpc.visitor;

public interface VisitInfoDownloadResponceOrBuilder extends
    // @@protoc_insertion_point(interface_extends:VisitorSystem_cq.VisitInfoDownloadResponce)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>int32 code = 1;</code>
   */
  int getCode();

  /**
   * <code>string message = 2;</code>
   */
  java.lang.String getMessage();
  /**
   * <code>string message = 2;</code>
   */
  com.google.protobuf.ByteString
      getMessageBytes();

  /**
   * <code>string server_secret = 3;</code>
   */
  java.lang.String getServerSecret();
  /**
   * <code>string server_secret = 3;</code>
   */
  com.google.protobuf.ByteString
      getServerSecretBytes();

  /**
   * <code>int64 serverVersion = 4;</code>
   */
  long getServerVersion();

  /**
   * <pre>
   *返回所有非本机的系统版本大于本机版本的访问记录
   * </pre>
   *
   * <code>repeated .VisitorSystem_cq.VisitInfoMessage visitInfoMessages = 5;</code>
   */
  java.util.List<com.ljzn.grpc.visitor.VisitInfoMessage> 
      getVisitInfoMessagesList();
  /**
   * <pre>
   *返回所有非本机的系统版本大于本机版本的访问记录
   * </pre>
   *
   * <code>repeated .VisitorSystem_cq.VisitInfoMessage visitInfoMessages = 5;</code>
   */
  com.ljzn.grpc.visitor.VisitInfoMessage getVisitInfoMessages(int index);
  /**
   * <pre>
   *返回所有非本机的系统版本大于本机版本的访问记录
   * </pre>
   *
   * <code>repeated .VisitorSystem_cq.VisitInfoMessage visitInfoMessages = 5;</code>
   */
  int getVisitInfoMessagesCount();
  /**
   * <pre>
   *返回所有非本机的系统版本大于本机版本的访问记录
   * </pre>
   *
   * <code>repeated .VisitorSystem_cq.VisitInfoMessage visitInfoMessages = 5;</code>
   */
  java.util.List<? extends com.ljzn.grpc.visitor.VisitInfoMessageOrBuilder> 
      getVisitInfoMessagesOrBuilderList();
  /**
   * <pre>
   *返回所有非本机的系统版本大于本机版本的访问记录
   * </pre>
   *
   * <code>repeated .VisitorSystem_cq.VisitInfoMessage visitInfoMessages = 5;</code>
   */
  com.ljzn.grpc.visitor.VisitInfoMessageOrBuilder getVisitInfoMessagesOrBuilder(
      int index);
}
