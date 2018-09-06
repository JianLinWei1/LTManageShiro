// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: client/client.service.proto

package com.ljzn.grpc.client;

public final class ClientService {
  private ClientService() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_VisitorSystem_cq_LoginRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_VisitorSystem_cq_LoginRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_VisitorSystem_cq_LoginResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_VisitorSystem_cq_LoginResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_VisitorSystem_cq_LogoutRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_VisitorSystem_cq_LogoutRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_VisitorSystem_cq_LogoutResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_VisitorSystem_cq_LogoutResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_VisitorSystem_cq_HeartbeatRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_VisitorSystem_cq_HeartbeatRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_VisitorSystem_cq_HeartbeatResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_VisitorSystem_cq_HeartbeatResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\033client/client.service.proto\022\020VisitorSy" +
      "stem_cq\032\033client/client.message.proto\032\035ve" +
      "rsion/version.message.proto\"h\n\014LoginRequ" +
      "est\022/\n\006client\030\001 \001(\0132\037.VisitorSystem_cq.C" +
      "lientMessage\022\025\n\rclient_secret\030\002 \001(\t\022\020\n\010b" +
      "elongId\030\003 \001(\005\"\227\001\n\rLoginResponse\022\014\n\004code\030" +
      "\001 \001(\005\022\017\n\007message\030\002 \001(\t\022\025\n\rserver_secret\030" +
      "\003 \001(\t\022\025\n\rserverVersion\030\004 \001(\003\0229\n\017versionM" +
      "essages\030\005 \003(\0132 .VisitorSystem_cq.Version" +
      "Message\"!\n\rLogoutRequest\022\020\n\010clientId\030\001 \001" +
      "(\t\"/\n\016LogoutResponse\022\014\n\004code\030\001 \001(\005\022\017\n\007me" +
      "ssage\030\002 \001(\t\"$\n\020HeartbeatRequest\022\020\n\010clien" +
      "tId\030\001 \001(\t\"C\n\021HeartbeatResponse\022\014\n\004code\030\001" +
      " \001(\005\022\017\n\007message\030\002 \001(\t\022\017\n\007counter\030\003 \001(\0032\350" +
      "\002\n\021ClientAuthService\022J\n\005Login\022\036.VisitorS" +
      "ystem_cq.LoginRequest\032\037.VisitorSystem_cq" +
      ".LoginResponse\"\000\022M\n\006Logout\022\037.VisitorSyst" +
      "em_cq.LogoutRequest\032 .VisitorSystem_cq.L" +
      "ogoutResponse\"\000\022V\n\tHeartbeat\022\".VisitorSy" +
      "stem_cq.HeartbeatRequest\032#.VisitorSystem" +
      "_cq.HeartbeatResponse\"\000\022`\n\017HeartbeatStre" +
      "am\022\".VisitorSystem_cq.HeartbeatRequest\032#" +
      ".VisitorSystem_cq.HeartbeatResponse\"\000(\0010" +
      "\001B!\n\024com.ljzn.grpc.clientP\001\242\002\006CLIENTb\006pr" +
      "oto3"
    };
    com.google.protobuf.Descriptors.FileDescriptor.InternalDescriptorAssigner assigner =
        new com.google.protobuf.Descriptors.FileDescriptor.    InternalDescriptorAssigner() {
          public com.google.protobuf.ExtensionRegistry assignDescriptors(
              com.google.protobuf.Descriptors.FileDescriptor root) {
            descriptor = root;
            return null;
          }
        };
    com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.ljzn.grpc.client.ClientMessageOuterClass.getDescriptor(),
          com.ljzn.grpc.version.VersionMessageOuterClass.getDescriptor(),
        }, assigner);
    internal_static_VisitorSystem_cq_LoginRequest_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_VisitorSystem_cq_LoginRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_VisitorSystem_cq_LoginRequest_descriptor,
        new java.lang.String[] { "Client", "ClientSecret", "BelongId", });
    internal_static_VisitorSystem_cq_LoginResponse_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_VisitorSystem_cq_LoginResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_VisitorSystem_cq_LoginResponse_descriptor,
        new java.lang.String[] { "Code", "Message", "ServerSecret", "ServerVersion", "VersionMessages", });
    internal_static_VisitorSystem_cq_LogoutRequest_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_VisitorSystem_cq_LogoutRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_VisitorSystem_cq_LogoutRequest_descriptor,
        new java.lang.String[] { "ClientId", });
    internal_static_VisitorSystem_cq_LogoutResponse_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_VisitorSystem_cq_LogoutResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_VisitorSystem_cq_LogoutResponse_descriptor,
        new java.lang.String[] { "Code", "Message", });
    internal_static_VisitorSystem_cq_HeartbeatRequest_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_VisitorSystem_cq_HeartbeatRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_VisitorSystem_cq_HeartbeatRequest_descriptor,
        new java.lang.String[] { "ClientId", });
    internal_static_VisitorSystem_cq_HeartbeatResponse_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_VisitorSystem_cq_HeartbeatResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_VisitorSystem_cq_HeartbeatResponse_descriptor,
        new java.lang.String[] { "Code", "Message", "Counter", });
    com.ljzn.grpc.client.ClientMessageOuterClass.getDescriptor();
    com.ljzn.grpc.version.VersionMessageOuterClass.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
