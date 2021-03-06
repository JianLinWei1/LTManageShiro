// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: visitor/visitor.message.proto

package com.ljzn.grpc.visitor;

public interface VisitorMessageOrBuilder extends
    // @@protoc_insertion_point(interface_extends:VisitorSystem_cq.VisitorMessage)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   *访客Id(身份证号或者其他)
   * </pre>
   *
   * <code>string visitorId = 1;</code>
   */
  java.lang.String getVisitorId();
  /**
   * <pre>
   *访客Id(身份证号或者其他)
   * </pre>
   *
   * <code>string visitorId = 1;</code>
   */
  com.google.protobuf.ByteString
      getVisitorIdBytes();

  /**
   * <pre>
   *证件类型
   * </pre>
   *
   * <code>int32 idType = 2;</code>
   */
  int getIdType();

  /**
   * <pre>
   *访客姓名
   * </pre>
   *
   * <code>string visitorName = 3;</code>
   */
  java.lang.String getVisitorName();
  /**
   * <pre>
   *访客姓名
   * </pre>
   *
   * <code>string visitorName = 3;</code>
   */
  com.google.protobuf.ByteString
      getVisitorNameBytes();

  /**
   * <pre>
   *性别
   * </pre>
   *
   * <code>string sex = 4;</code>
   */
  java.lang.String getSex();
  /**
   * <pre>
   *性别
   * </pre>
   *
   * <code>string sex = 4;</code>
   */
  com.google.protobuf.ByteString
      getSexBytes();

  /**
   * <pre>
   * 民族
   * </pre>
   *
   * <code>string nation = 5;</code>
   */
  java.lang.String getNation();
  /**
   * <pre>
   * 民族
   * </pre>
   *
   * <code>string nation = 5;</code>
   */
  com.google.protobuf.ByteString
      getNationBytes();

  /**
   * <pre>
   * 生日
   * </pre>
   *
   * <code>string birthday = 6;</code>
   */
  java.lang.String getBirthday();
  /**
   * <pre>
   * 生日
   * </pre>
   *
   * <code>string birthday = 6;</code>
   */
  com.google.protobuf.ByteString
      getBirthdayBytes();

  /**
   * <pre>
   *地址
   * </pre>
   *
   * <code>string address = 7;</code>
   */
  java.lang.String getAddress();
  /**
   * <pre>
   *地址
   * </pre>
   *
   * <code>string address = 7;</code>
   */
  com.google.protobuf.ByteString
      getAddressBytes();

  /**
   * <pre>
   *颁发机构
   * </pre>
   *
   * <code>string depart = 8;</code>
   */
  java.lang.String getDepart();
  /**
   * <pre>
   *颁发机构
   * </pre>
   *
   * <code>string depart = 8;</code>
   */
  com.google.protobuf.ByteString
      getDepartBytes();

  /**
   * <pre>
   *有效开始日期
   * </pre>
   *
   * <code>string validityBegin = 9;</code>
   */
  java.lang.String getValidityBegin();
  /**
   * <pre>
   *有效开始日期
   * </pre>
   *
   * <code>string validityBegin = 9;</code>
   */
  com.google.protobuf.ByteString
      getValidityBeginBytes();

  /**
   * <pre>
   *有效结束日期
   * </pre>
   *
   * <code>string validityEnd = 10;</code>
   */
  java.lang.String getValidityEnd();
  /**
   * <pre>
   *有效结束日期
   * </pre>
   *
   * <code>string validityEnd = 10;</code>
   */
  com.google.protobuf.ByteString
      getValidityEndBytes();

  /**
   * <pre>
   *证件照
   * </pre>
   *
   * <code>bytes idPhoto = 11;</code>
   */
  com.google.protobuf.ByteString getIdPhoto();

  /**
   * <pre>
   *现场照
   * </pre>
   *
   * <code>bytes cameraPhoto = 12;</code>
   */
  com.google.protobuf.ByteString getCameraPhoto();

  /**
   * <pre>
   *现场照特征
   * </pre>
   *
   * <code>bytes cameraFeature = 13;</code>
   */
  com.google.protobuf.ByteString getCameraFeature();

  /**
   * <pre>
   *指纹特征
   * </pre>
   *
   * <code>bytes fingerFeature = 14;</code>
   */
  com.google.protobuf.ByteString getFingerFeature();

  /**
   * <pre>
   *操作
   * </pre>
   *
   * <code>int32 action = 15;</code>
   */
  int getAction();

  /**
   * <pre>
   *版本
   * </pre>
   *
   * <code>int64 version = 16;</code>
   */
  long getVersion();

  /**
   * <pre>
   *人脸验证分值
   * </pre>
   *
   * <code>float faceVerifyScore = 17;</code>
   */
  float getFaceVerifyScore();

  /**
   * <pre>
   *人脸验证结果
   * </pre>
   *
   * <code>string faceVerifyResult = 18;</code>
   */
  java.lang.String getFaceVerifyResult();
  /**
   * <pre>
   *人脸验证结果
   * </pre>
   *
   * <code>string faceVerifyResult = 18;</code>
   */
  com.google.protobuf.ByteString
      getFaceVerifyResultBytes();

  /**
   * <pre>
   *日期
   * </pre>
   *
   * <code>int64 dateTime = 19;</code>
   */
  long getDateTime();

  /**
   * <pre>
   *联系方式
   * </pre>
   *
   * <code>string contact = 20;</code>
   */
  java.lang.String getContact();
  /**
   * <pre>
   *联系方式
   * </pre>
   *
   * <code>string contact = 20;</code>
   */
  com.google.protobuf.ByteString
      getContactBytes();

  /**
   * <pre>
   *本系统分配的ID
   * </pre>
   *
   * <code>int32 belongId = 21;</code>
   */
  int getBelongId();
}
