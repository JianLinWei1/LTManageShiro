// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: company/company.message.proto

package com.ljzn.grpc.company;

/**
 * Protobuf type {@code VisitorSystem_cq.CompanyMessage}
 */
public  final class CompanyMessage extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:VisitorSystem_cq.CompanyMessage)
    CompanyMessageOrBuilder {
private static final long serialVersionUID = 0L;
  // Use CompanyMessage.newBuilder() to construct.
  private CompanyMessage(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private CompanyMessage() {
    belongId_ = 0;
    description_ = "";
    parentId_ = 0;
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private CompanyMessage(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    int mutable_bitField0_ = 0;
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          default: {
            if (!parseUnknownFieldProto3(
                input, unknownFields, extensionRegistry, tag)) {
              done = true;
            }
            break;
          }
          case 8: {

            belongId_ = input.readInt32();
            break;
          }
          case 18: {
            java.lang.String s = input.readStringRequireUtf8();

            description_ = s;
            break;
          }
          case 24: {

            parentId_ = input.readInt32();
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.ljzn.grpc.company.CompanyMessageOuterClass.internal_static_VisitorSystem_cq_CompanyMessage_descriptor;
  }

  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.ljzn.grpc.company.CompanyMessageOuterClass.internal_static_VisitorSystem_cq_CompanyMessage_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.ljzn.grpc.company.CompanyMessage.class, com.ljzn.grpc.company.CompanyMessage.Builder.class);
  }

  public static final int BELONGID_FIELD_NUMBER = 1;
  private int belongId_;
  /**
   * <pre>
   *uuid
   * </pre>
   *
   * <code>int32 belongId = 1;</code>
   */
  public int getBelongId() {
    return belongId_;
  }

  public static final int DESCRIPTION_FIELD_NUMBER = 2;
  private volatile java.lang.Object description_;
  /**
   * <code>string description = 2;</code>
   */
  public java.lang.String getDescription() {
    java.lang.Object ref = description_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      description_ = s;
      return s;
    }
  }
  /**
   * <code>string description = 2;</code>
   */
  public com.google.protobuf.ByteString
      getDescriptionBytes() {
    java.lang.Object ref = description_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      description_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int PARENTID_FIELD_NUMBER = 3;
  private int parentId_;
  /**
   * <code>int32 parentId = 3;</code>
   */
  public int getParentId() {
    return parentId_;
  }

  private byte memoizedIsInitialized = -1;
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (belongId_ != 0) {
      output.writeInt32(1, belongId_);
    }
    if (!getDescriptionBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, description_);
    }
    if (parentId_ != 0) {
      output.writeInt32(3, parentId_);
    }
    unknownFields.writeTo(output);
  }

  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (belongId_ != 0) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt32Size(1, belongId_);
    }
    if (!getDescriptionBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, description_);
    }
    if (parentId_ != 0) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt32Size(3, parentId_);
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof com.ljzn.grpc.company.CompanyMessage)) {
      return super.equals(obj);
    }
    com.ljzn.grpc.company.CompanyMessage other = (com.ljzn.grpc.company.CompanyMessage) obj;

    boolean result = true;
    result = result && (getBelongId()
        == other.getBelongId());
    result = result && getDescription()
        .equals(other.getDescription());
    result = result && (getParentId()
        == other.getParentId());
    result = result && unknownFields.equals(other.unknownFields);
    return result;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    hash = (37 * hash) + BELONGID_FIELD_NUMBER;
    hash = (53 * hash) + getBelongId();
    hash = (37 * hash) + DESCRIPTION_FIELD_NUMBER;
    hash = (53 * hash) + getDescription().hashCode();
    hash = (37 * hash) + PARENTID_FIELD_NUMBER;
    hash = (53 * hash) + getParentId();
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.ljzn.grpc.company.CompanyMessage parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(com.ljzn.grpc.company.CompanyMessage prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * Protobuf type {@code VisitorSystem_cq.CompanyMessage}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:VisitorSystem_cq.CompanyMessage)
      com.ljzn.grpc.company.CompanyMessageOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.ljzn.grpc.company.CompanyMessageOuterClass.internal_static_VisitorSystem_cq_CompanyMessage_descriptor;
    }

    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.ljzn.grpc.company.CompanyMessageOuterClass.internal_static_VisitorSystem_cq_CompanyMessage_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.ljzn.grpc.company.CompanyMessage.class, com.ljzn.grpc.company.CompanyMessage.Builder.class);
    }

    // Construct using com.ljzn.grpc.company.CompanyMessage.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
      }
    }
    public Builder clear() {
      super.clear();
      belongId_ = 0;

      description_ = "";

      parentId_ = 0;

      return this;
    }

    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.ljzn.grpc.company.CompanyMessageOuterClass.internal_static_VisitorSystem_cq_CompanyMessage_descriptor;
    }

    public com.ljzn.grpc.company.CompanyMessage getDefaultInstanceForType() {
      return com.ljzn.grpc.company.CompanyMessage.getDefaultInstance();
    }

    public com.ljzn.grpc.company.CompanyMessage build() {
      com.ljzn.grpc.company.CompanyMessage result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    public com.ljzn.grpc.company.CompanyMessage buildPartial() {
      com.ljzn.grpc.company.CompanyMessage result = new com.ljzn.grpc.company.CompanyMessage(this);
      result.belongId_ = belongId_;
      result.description_ = description_;
      result.parentId_ = parentId_;
      onBuilt();
      return result;
    }

    public Builder clone() {
      return (Builder) super.clone();
    }
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return (Builder) super.setField(field, value);
    }
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return (Builder) super.clearField(field);
    }
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return (Builder) super.clearOneof(oneof);
    }
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return (Builder) super.setRepeatedField(field, index, value);
    }
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return (Builder) super.addRepeatedField(field, value);
    }
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof com.ljzn.grpc.company.CompanyMessage) {
        return mergeFrom((com.ljzn.grpc.company.CompanyMessage)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.ljzn.grpc.company.CompanyMessage other) {
      if (other == com.ljzn.grpc.company.CompanyMessage.getDefaultInstance()) return this;
      if (other.getBelongId() != 0) {
        setBelongId(other.getBelongId());
      }
      if (!other.getDescription().isEmpty()) {
        description_ = other.description_;
        onChanged();
      }
      if (other.getParentId() != 0) {
        setParentId(other.getParentId());
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    public final boolean isInitialized() {
      return true;
    }

    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      com.ljzn.grpc.company.CompanyMessage parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (com.ljzn.grpc.company.CompanyMessage) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private int belongId_ ;
    /**
     * <pre>
     *uuid
     * </pre>
     *
     * <code>int32 belongId = 1;</code>
     */
    public int getBelongId() {
      return belongId_;
    }
    /**
     * <pre>
     *uuid
     * </pre>
     *
     * <code>int32 belongId = 1;</code>
     */
    public Builder setBelongId(int value) {
      
      belongId_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     *uuid
     * </pre>
     *
     * <code>int32 belongId = 1;</code>
     */
    public Builder clearBelongId() {
      
      belongId_ = 0;
      onChanged();
      return this;
    }

    private java.lang.Object description_ = "";
    /**
     * <code>string description = 2;</code>
     */
    public java.lang.String getDescription() {
      java.lang.Object ref = description_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        description_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string description = 2;</code>
     */
    public com.google.protobuf.ByteString
        getDescriptionBytes() {
      java.lang.Object ref = description_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        description_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string description = 2;</code>
     */
    public Builder setDescription(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      description_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string description = 2;</code>
     */
    public Builder clearDescription() {
      
      description_ = getDefaultInstance().getDescription();
      onChanged();
      return this;
    }
    /**
     * <code>string description = 2;</code>
     */
    public Builder setDescriptionBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      description_ = value;
      onChanged();
      return this;
    }

    private int parentId_ ;
    /**
     * <code>int32 parentId = 3;</code>
     */
    public int getParentId() {
      return parentId_;
    }
    /**
     * <code>int32 parentId = 3;</code>
     */
    public Builder setParentId(int value) {
      
      parentId_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>int32 parentId = 3;</code>
     */
    public Builder clearParentId() {
      
      parentId_ = 0;
      onChanged();
      return this;
    }
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFieldsProto3(unknownFields);
    }

    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:VisitorSystem_cq.CompanyMessage)
  }

  // @@protoc_insertion_point(class_scope:VisitorSystem_cq.CompanyMessage)
  private static final com.ljzn.grpc.company.CompanyMessage DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.ljzn.grpc.company.CompanyMessage();
  }

  public static com.ljzn.grpc.company.CompanyMessage getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<CompanyMessage>
      PARSER = new com.google.protobuf.AbstractParser<CompanyMessage>() {
    public CompanyMessage parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new CompanyMessage(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<CompanyMessage> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<CompanyMessage> getParserForType() {
    return PARSER;
  }

  public com.ljzn.grpc.company.CompanyMessage getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}
