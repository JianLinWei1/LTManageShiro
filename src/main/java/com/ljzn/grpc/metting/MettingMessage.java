// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: metting/metting.message.proto

package com.ljzn.grpc.metting;

public final class MettingMessage {
  private MettingMessage() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_MettingSystem_MettingEmpInfo_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_MettingSystem_MettingEmpInfo_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\035metting/metting.message.proto\022\rMetting" +
      "System\"x\n\016MettingEmpInfo\022\021\n\tmettingId\030\001 " +
      "\001(\005\022\023\n\013mettingName\030\002 \001(\t\022\022\n\nemployeeId\030\003" +
      " \001(\t\022\024\n\014employeeName\030\004 \001(\t\022\024\n\014photoFeatu" +
      "re\030\005 \001(\014B#\n\025com.ljzn.grpc.mettingP\001\242\002\007ME" +
      "TTINGb\006proto3"
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
        }, assigner);
    internal_static_MettingSystem_MettingEmpInfo_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_MettingSystem_MettingEmpInfo_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_MettingSystem_MettingEmpInfo_descriptor,
        new java.lang.String[] { "MettingId", "MettingName", "EmployeeId", "EmployeeName", "PhotoFeature", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}
