using System.Collections;
using AuthServer.Sample.Extensions;
using AuthServer.Sample.Models;
using Microsoft.AspNetCore.Mvc.TagHelpers.Cache;

namespace AuthServer.Sample.Tests;

public class StringExtensionsTest
{
    [Fact]
    public void TestBase64StringFormAndToConversion()
    {
        var plainText = "SampleText";
        var base64String = plainText.ToBase64String();
        var toPlainText = base64String.FromBase64String();
        Assert.Equal(toPlainText, plainText);
    }

    [Fact]
    public void FromAndToObjectTest()
    {
        var testData = new OAuthTokenRequest
        {
            client_id = "test",
            client_secret = "test",
        };

        var queryString = testData.ToDictionary().ToQueryString();
        Assert.NotNull(queryString);
        var base64String = queryString.ToBase64String();
        var toPlainText = base64String.FromBase64String();
        Assert.NotNull(toPlainText);
        var toDictionary = toPlainText.ToDictionary();
        var toTestData= toDictionary.ToObject<OAuthTokenRequest>();

        Assert.NotNull(toTestData);

        System.Collections.ArrayList arrayList = new System.Collections.ArrayList
        {
            testData,
            queryString,
            10
        };
        var aa = arrayList[0];
        var sl = new System.Collections.SortedList();
        
        var ht = new System.Collections.Hashtable();
        ht.Add(1, 1);
        var hs = new System.Collections.Generic.HashSet<string>();
        var ss = new System.Collections.Generic.SortedSet<string>();
    }

    //[Fact]
    [Theory]
    [InlineData(1)]
    [MemberData(nameof(TestData))]
    public void Test(int ab)
    {
        MyClassA a = new MyClassC();
        var ga= a.Get();
        MyClassB b = new MyClassC();
        var gb = b.Get();

        MyClassC c = new MyClassC();
        var gc = c.Get();


        var s = new MyStruct(10);
    }

    public static IEnumerable<object[]> TestData()
    {
        yield return new object[] { 1, 2, 3 };
    }
    class MyClassA
    {
        public MyClassA()
        {
            ; // First 
        }

        public MyClassA(int a)
        {
            ; //First
        }

        public virtual int Get()
        {
            return 10;
        }

        public IEnumerable<int> Test()
        {
            yield return 1;
            yield return 1;
            yield return 1;
          
        }
    }

    class MyClassB : MyClassA
    {
        public MyClassB() : base(10)
        {
            ; //second
        }

        public override int Get()
        {
            return 11;
        }
    }
    class MyClassC : MyClassB
    {
        public MyClassC():base()
        {
            ; // third
        }

        public new int Get()
        {
            return 12;
        }
    }

    struct MyStruct
    {
        //public MyStruct()
        //{
        //    ;
        //}

        public MyStruct(int a)
        {
            ;
        }

    }
}